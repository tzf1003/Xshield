use chrono::{SecondsFormat, Utc};
mod reconcile;

use reconcile::{IncompleteRequest, incomplete_requests};
use serde::Serialize;
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::task::JoinError;
use uuid::Uuid;
use xshield_audit::{
    JournalError, JournalKey, JournalLimits, JournalReceipt, JournalRecord, LocalJournal,
    RecoveryReport,
};
use xshield_core::audit::ReasonCode;
use xshield_core::domain::{EventId, InvalidValue, PageEvidenceId};
use zeroize::Zeroizing;

use xshield_gateway::request_crypto::{
    RequestCryptoCompatibilityRule, RequestCryptoEvidence, RequestCryptoObserveRule,
    RequestCryptoRule,
};
use xshield_gateway::response_crypto::{ResponseCryptoEvidence, ResponseCryptoRule};
use xshield_gateway::sensor::SensorObservation;
use xshield_gateway::{GatewayConfig, GatewayDecision, GatewayOutcome};
use xshield_postgres::SensorSession;

/// Shared, read-only view of the durable-audit barrier state.
///
/// It carries no journal access: it only reports whether admission would
/// currently fail closed because a durability error was observed.
#[derive(Clone)]
pub(crate) struct AuditReadiness {
    ready: Arc<AtomicBool>,
    failure_code: Arc<AtomicU8>,
}

impl AuditReadiness {
    pub(crate) fn is_ready(&self) -> bool {
        barrier_open(&self.ready, &self.failure_code)
    }
}

// One definition for the admission barrier and its health view, so they cannot drift.
fn barrier_open(ready: &AtomicBool, failure_code: &AtomicU8) -> bool {
    ready.load(Ordering::Acquire) && failure_code.load(Ordering::Acquire) == 0
}

#[derive(Clone)]
pub(crate) struct DurableAudit {
    /// `None` only while a failed writer has been released and its replacement
    /// is not yet open; appends then fail closed with `Unavailable`.
    journal: Arc<Mutex<Option<LocalJournal>>>,
    ready: Arc<AtomicBool>,
    failure_code: Arc<AtomicU8>,
    tenant_id: String,
    site_id: String,
    policy_revision: String,
    producer_id: String,
    /// What it takes to reopen the journal after a durability failure; absent
    /// for writers built without a recoverable key.
    reopen: Option<Arc<ReopenSource>>,
}

/// Material for reopening the journal in process. `LocalJournal::open` is the
/// only supported way back from a poisoned or quota-stale writer: it
/// re-authenticates every segment, repairs an incomplete tail and recomputes
/// the bytes in use from disk.
struct ReopenSource {
    key_hex: Zeroizing<String>,
    directory: PathBuf,
    key_id: String,
    limits: JournalLimits,
    /// The journal only reopens while it is under this size, so a nearly full
    /// directory cannot flap between open and closed.
    high_watermark_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct AdmissionAudit {
    pub(crate) decision_event_id: String,
    pub(crate) forward_intent_event_id: Option<String>,
    pub(crate) next_request_sequence: u32,
}

pub(crate) struct AdmissionFacts<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) trace_id: &'a str,
    pub(crate) method: &'a str,
    pub(crate) decision: &'a GatewayDecision,
    pub(crate) duration_us: u64,
    pub(crate) request_crypto: Option<&'a RequestCryptoAudit>,
    pub(crate) sensor_observations: &'a [SensorObservationAudit],
    pub(crate) sensor_bootstrap: Option<&'a SensorBootstrapAudit>,
    pub(crate) forward_origin: bool,
}

/// What one versioned bootstrap delivered. Counts only: references never
/// enter the journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SensorBootstrapAudit {
    delivered: usize,
}

impl SensorBootstrapAudit {
    pub(crate) const fn new(delivered: usize) -> Self {
        Self { delivered }
    }
}

/// Result of issuing a page root's declared actions on delivery. A failure
/// never withholds the page; it is recorded here and the page simply holds no
/// references, so its gated requests stay denied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PageActionAudit {
    outcome: &'static str,
    reason_code: ReasonCode,
    mapping_revision: String,
}

impl PageActionAudit {
    pub(crate) fn issued(reason_code: ReasonCode, mapping_revision: &str) -> Self {
        Self {
            outcome: "PASS",
            reason_code,
            mapping_revision: mapping_revision.to_owned(),
        }
    }

    /// Ineligibility, conflict or capacity is a deterministic denial; store
    /// and clock failures are dependency errors.
    pub(crate) fn failed(reason_code: ReasonCode, mapping_revision: &str) -> Self {
        let outcome = match reason_code {
            ReasonCode::IdentityStoreUnavailable | ReasonCode::ClockUnavailable => "ERROR",
            _ => "DENY",
        };
        Self {
            outcome,
            reason_code,
            mapping_revision: mapping_revision.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SensorObservationAudit {
    binding_id: String,
    auth_epoch: u64,
    authenticated: bool,
    build_ref: String,
    page_handle: String,
    navigation_id: String,
    action_hint: Option<String>,
    client_request_id: Option<String>,
    client_event_seq: u32,
    visibility: &'static str,
    event_type: &'static str,
    callsite_fingerprint: Option<String>,
}

impl SensorObservationAudit {
    pub(crate) fn new(session: &SensorSession, observation: &SensorObservation) -> Self {
        Self {
            binding_id: session.binding_id().as_str().to_owned(),
            auth_epoch: session.epoch().value(),
            authenticated: session.authenticated(),
            build_ref: observation.build_ref().to_owned(),
            page_handle: observation.page_handle().to_owned(),
            navigation_id: observation.navigation_id().to_owned(),
            action_hint: observation.action_hint().map(str::to_owned),
            client_request_id: observation
                .client_request_id()
                .map(|request_id| request_id.as_str().to_owned()),
            client_event_seq: observation.client_event_seq(),
            visibility: observation.visibility().as_str(),
            event_type: observation.event_type().as_str(),
            callsite_fingerprint: observation.callsite_fingerprint().map(str::to_owned),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RequestCryptoAudit {
    coverage_mode: &'static str,
    algorithm: Option<&'static str>,
    adapter_revision: String,
    key_id: Option<String>,
    approval_ref: Option<String>,
    source_evidence_ref: Option<String>,
    message_id: Option<String>,
    nonce_sha256: Option<String>,
    issued_at: Option<u64>,
    expires_at: Option<u64>,
    envelope_sha256: Option<String>,
    rebuilt_sha256: Option<String>,
    outcome: &'static str,
    reason_code: ReasonCode,
    duration_us: u64,
}

impl RequestCryptoAudit {
    pub(crate) fn passed(evidence: &RequestCryptoEvidence, duration_us: u64) -> Self {
        Self {
            coverage_mode: "ENFORCE",
            algorithm: Some(evidence.algorithm()),
            adapter_revision: evidence.adapter_revision().to_owned(),
            key_id: Some(evidence.key_id().to_owned()),
            approval_ref: None,
            source_evidence_ref: None,
            message_id: Some(evidence.message_id().to_owned()),
            nonce_sha256: Some(evidence.nonce_sha256().to_owned()),
            issued_at: Some(evidence.issued_at().value()),
            expires_at: Some(evidence.expires_at().value()),
            envelope_sha256: Some(evidence.envelope_sha256().to_owned()),
            rebuilt_sha256: Some(evidence.rebuilt_sha256().to_owned()),
            outcome: "PASS",
            reason_code: ReasonCode::RequestCryptoDecoded,
            duration_us,
        }
    }

    pub(crate) fn observed(rule: &RequestCryptoObserveRule) -> Self {
        Self {
            coverage_mode: "OBSERVE",
            algorithm: None,
            adapter_revision: rule.adapter_revision().to_owned(),
            key_id: None,
            approval_ref: None,
            source_evidence_ref: None,
            message_id: None,
            nonce_sha256: None,
            issued_at: None,
            expires_at: None,
            envelope_sha256: None,
            rebuilt_sha256: None,
            outcome: "PASS",
            reason_code: ReasonCode::RequestCryptoObservedOpaque,
            duration_us: 0,
        }
    }

    pub(crate) fn compatible(
        rule: &RequestCryptoCompatibilityRule,
        page_evidence_id: &PageEvidenceId,
        duration_us: u64,
    ) -> Self {
        Self {
            coverage_mode: "COMPATIBILITY",
            algorithm: None,
            adapter_revision: rule.adapter_revision().to_owned(),
            key_id: None,
            approval_ref: Some(rule.approval_ref().to_owned()),
            source_evidence_ref: Some(page_evidence_id.as_str().to_owned()),
            message_id: None,
            nonce_sha256: None,
            issued_at: None,
            expires_at: None,
            envelope_sha256: None,
            rebuilt_sha256: None,
            outcome: "PASS",
            reason_code: ReasonCode::RequestCryptoCompatibilityOpaque,
            duration_us,
        }
    }

    pub(crate) fn compatibility_failed(
        rule: &RequestCryptoCompatibilityRule,
        page_evidence_id: Option<&PageEvidenceId>,
        reason_code: ReasonCode,
        duration_us: u64,
    ) -> Self {
        Self {
            coverage_mode: "COMPATIBILITY",
            algorithm: None,
            adapter_revision: rule.adapter_revision().to_owned(),
            key_id: None,
            approval_ref: Some(rule.approval_ref().to_owned()),
            source_evidence_ref: page_evidence_id.map(|value| value.as_str().to_owned()),
            message_id: None,
            nonce_sha256: None,
            issued_at: None,
            expires_at: None,
            envelope_sha256: None,
            rebuilt_sha256: None,
            outcome: "DENY",
            reason_code,
            duration_us,
        }
    }

    pub(crate) fn failed(
        rule: &RequestCryptoRule,
        reason_code: ReasonCode,
        duration_us: u64,
    ) -> Self {
        let outcome = match reason_code {
            ReasonCode::RequestBufferCapacityExhausted
            | ReasonCode::RequestCryptoKeyUnavailable
            | ReasonCode::RequestCryptoReplayStoreUnavailable => "ERROR",
            _ => "DENY",
        };
        Self {
            coverage_mode: "ENFORCE",
            algorithm: Some(rule.algorithm()),
            adapter_revision: rule.adapter_revision().to_owned(),
            key_id: Some(rule.key_id().to_owned()),
            approval_ref: None,
            source_evidence_ref: None,
            message_id: None,
            nonce_sha256: None,
            issued_at: None,
            expires_at: None,
            envelope_sha256: None,
            rebuilt_sha256: None,
            outcome,
            reason_code,
            duration_us,
        }
    }
}

pub(crate) struct FinalFacts<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) trace_id: &'a str,
    pub(crate) method: &'a str,
    pub(crate) decision: &'a GatewayDecision,
    pub(crate) admission: &'a AdmissionAudit,
    pub(crate) status: u16,
    pub(crate) duration_us: u64,
    pub(crate) proxy_error: bool,
    pub(crate) response_failure: Option<ReasonCode>,
    pub(crate) origin_status: Option<u16>,
    /// The entire buffered response was validated; this is not business confirmation.
    pub(crate) origin_response_complete: bool,
    pub(crate) response_crypto: Option<&'a ResponseCryptoAudit>,
    pub(crate) sensor_html: Option<&'a SensorHtmlAudit>,
    pub(crate) page_actions: Option<&'a PageActionAudit>,
    pub(crate) response_source: ResponseSource,
}

#[derive(Clone, Debug)]
pub(crate) struct SensorHtmlAudit {
    adapter_revision: String,
    origin_sha256: String,
    injected_sha256: String,
    csp_nonce_applied: bool,
}

impl SensorHtmlAudit {
    pub(crate) fn new(
        adapter_revision: String,
        origin_sha256: String,
        injected_sha256: String,
        csp_nonce_applied: bool,
    ) -> Self {
        Self {
            adapter_revision,
            origin_sha256,
            injected_sha256,
            csp_nonce_applied,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseSource {
    Origin,
    Edge,
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseCryptoAudit {
    algorithm: &'static str,
    adapter_revision: String,
    key_id: String,
    message_id: Option<String>,
    nonce_sha256: Option<String>,
    issued_at: Option<u64>,
    expires_at: Option<u64>,
    origin_sha256: Option<String>,
    envelope_sha256: Option<String>,
    outcome: &'static str,
    reason_code: ReasonCode,
    duration_us: u64,
}

impl ResponseCryptoAudit {
    pub(crate) fn passed(evidence: &ResponseCryptoEvidence, duration_us: u64) -> Self {
        Self {
            algorithm: evidence.algorithm(),
            adapter_revision: evidence.adapter_revision().to_owned(),
            key_id: evidence.key_id().to_owned(),
            message_id: Some(evidence.message_id().to_owned()),
            nonce_sha256: Some(evidence.nonce_sha256().to_owned()),
            issued_at: Some(evidence.issued_at().value()),
            expires_at: Some(evidence.expires_at().value()),
            origin_sha256: Some(evidence.origin_sha256().to_owned()),
            envelope_sha256: Some(evidence.envelope_sha256().to_owned()),
            outcome: "PASS",
            reason_code: ReasonCode::ResponseCryptoEncoded,
            duration_us,
        }
    }

    pub(crate) fn failed(
        rule: &ResponseCryptoRule,
        reason_code: ReasonCode,
        duration_us: u64,
    ) -> Self {
        Self {
            algorithm: rule.algorithm(),
            adapter_revision: rule.adapter_revision().to_owned(),
            key_id: rule.key_id().to_owned(),
            message_id: None,
            nonce_sha256: None,
            issued_at: None,
            expires_at: None,
            origin_sha256: None,
            envelope_sha256: None,
            outcome: "ERROR",
            reason_code,
            duration_us,
        }
    }
}

struct FinalOrigin {
    state: &'static str,
    event_type: &'static str,
    reason_code: &'static str,
    status: Option<u16>,
}

impl DurableAudit {
    pub(crate) fn open(config: &GatewayConfig, key: JournalKey) -> Result<Self, DurableAuditError> {
        let (journal, recovery) = LocalJournal::open(
            config.audit_directory(),
            config.audit_key_id(),
            key,
            config.audit_limits(),
        )?;
        let incomplete = incomplete_requests(&journal, config)?;
        let audit = Self {
            journal: Arc::new(Mutex::new(Some(journal))),
            ready: Arc::new(AtomicBool::new(true)),
            failure_code: Arc::new(AtomicU8::new(0)),
            tenant_id: config.tenant_id().as_str().to_owned(),
            site_id: config.site_id().as_str().to_owned(),
            policy_revision: config.policy_revision().as_str().to_owned(),
            producer_id: config.audit_producer_id().to_owned(),
            reopen: None,
        };
        if recovery.truncated_bytes > 0 {
            audit.record_recovery(recovery)?;
        }
        audit.record_incomplete(incomplete)?;
        Ok(audit)
    }

    /// Opens the journal like [`Self::open`] and keeps what [`Self::try_reopen`]
    /// needs to bring the barrier back after a durability failure.
    pub(crate) fn open_recoverable(
        config: &GatewayConfig,
        key_hex: &str,
    ) -> Result<Self, DurableAuditError> {
        let mut audit = Self::open(config, JournalKey::from_hex(key_hex)?)?;
        audit.reopen = Some(Arc::new(ReopenSource {
            key_hex: Zeroizing::new(key_hex.to_owned()),
            directory: config.audit_directory().to_owned(),
            key_id: config.audit_key_id().to_owned(),
            limits: config.audit_limits(),
            high_watermark_bytes: config.audit_high_watermark_bytes(),
        }));
        Ok(audit)
    }

    pub(crate) fn is_ready(&self) -> bool {
        barrier_open(&self.ready, &self.failure_code)
    }

    /// Returns a cheap shared view of the durable-audit barrier. Health probes
    /// observe the same flags that make admission fail closed.
    pub(crate) fn readiness(&self) -> AuditReadiness {
        AuditReadiness {
            ready: Arc::clone(&self.ready),
            failure_code: Arc::clone(&self.failure_code),
        }
    }

    /// Reuses the durable writer while binding emitted event scope to the
    /// selected site snapshot. The deployment key/journal remains shared;
    /// per-site journal directories require a supervised writer registry.
    pub(crate) fn scoped(&self, config: &GatewayConfig) -> Self {
        Self {
            journal: Arc::clone(&self.journal),
            ready: Arc::clone(&self.ready),
            failure_code: Arc::clone(&self.failure_code),
            tenant_id: config.tenant_id().as_str().to_owned(),
            site_id: config.site_id().as_str().to_owned(),
            policy_revision: config.policy_revision().as_str().to_owned(),
            producer_id: config.audit_producer_id().to_owned(),
            reopen: self.reopen.clone(),
        }
    }

    /// Durably records the refusals counted for one listener port: requests no
    /// site snapshot routes. One bounded `edge.unrouted_denied` summary stands
    /// for all of them (see `unrouted.rs`); the barrier applies like any write.
    pub(crate) async fn record_unrouted(
        &self,
        summary: &crate::unrouted::UnroutedSummary,
    ) -> Result<(), DurableAuditError> {
        let event = PendingEvent::new(
            new_event_id()?,
            "edge.unrouted_denied",
            1,
            Vec::new(),
            Payload::Unrouted {
                listener_port: summary.listener_port,
                denied_count: summary.denied_count,
                first_seen_unix: summary.first_seen_unix,
                last_seen_unix: summary.last_seen_unix,
                sample_host: summary.sample_host.clone(),
                reason_code: ReasonCode::HostNotRouted.as_str(),
            },
        );
        self.append(
            BatchContext {
                request_id: None,
                trace_id: new_trace_id(),
            },
            vec![event],
        )
        .await?;
        Ok(())
    }

    /// Tries once to bring a closed barrier back; admission stays refused until
    /// this succeeds.
    ///
    /// The journal is only touched when its directory is below the high
    /// watermark, so probing a still-full journal costs one directory listing
    /// and creates no segment. The old writer is released first (the single
    /// writer lock forbids two), the journal is reopened through recovery, and
    /// the reopen is recorded durably (`audit.recovered` /
    /// `AUDIT_BARRIER_REOPENED`) before the flags flip, so the gap is evident
    /// in the audit trail. Requests whose terminal event was lost during the
    /// outage are repaired by the existing startup reconciliation, not here: a
    /// request may still be in flight and must not receive a second terminal.
    ///
    /// # Errors
    /// Returns the reason the barrier stays closed.
    pub(crate) async fn try_reopen(&self) -> Result<(), DurableAuditError> {
        if self.is_ready() {
            return Ok(());
        }
        let source = self
            .reopen
            .as_ref()
            .map(Arc::clone)
            .ok_or(DurableAuditError::Unavailable)?;
        let journal = Arc::clone(&self.journal);
        let scope = (
            self.tenant_id.clone(),
            self.site_id.clone(),
            self.policy_revision.clone(),
            self.producer_id.clone(),
        );
        tokio::task::spawn_blocking(move || {
            reopen_blocking(&journal, &source, (&scope.0, &scope.1, &scope.2, &scope.3))
        })
        .await
        .map_err(DurableAuditError::Join)??;
        self.failure_code.store(0, Ordering::Release);
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn observe_failure(&self, error: &DurableAuditError) {
        let code = match error {
            DurableAuditError::Journal(_) => 1,
            DurableAuditError::Json(_) => 2,
            DurableAuditError::Join(_) => 3,
            DurableAuditError::InvalidId(_) => 4,
            DurableAuditError::LockPoisoned => 5,
            DurableAuditError::SequenceExhausted => 6,
            DurableAuditError::ReceiptMismatch => 7,
            DurableAuditError::Unavailable => 8,
            DurableAuditError::InvalidHistoricalEvent => 9,
        };
        self.failure_code.store(code, Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

    // The event sequence stays visible here so its causal and request ordering
    // can be reviewed as one durability transaction.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn commit_admission(
        &self,
        facts: AdmissionFacts<'_>,
    ) -> Result<AdmissionAudit, DurableAuditError> {
        if !self.is_ready() {
            return Err(DurableAuditError::Unavailable);
        }
        let accepted_id = new_event_id()?;
        let stage_id = new_event_id()?;
        let decision_id = new_event_id()?;
        let operation_id = operation_id(facts.decision);
        let outcome = stage_outcome(facts.decision.outcome);
        let decision = decision_name(facts.decision.outcome);
        let mut events = vec![
            PendingEvent::new(
                accepted_id.clone(),
                "request.accepted",
                1,
                Vec::new(),
                Payload::RequestAccepted {
                    method: facts.method.to_owned(),
                    operation_id: operation_id.clone(),
                    origin_state: "not_sent",
                },
            ),
            PendingEvent::new(
                stage_id.clone(),
                "stage.completed",
                2,
                vec![accepted_id.as_str().to_owned()],
                Payload::StageCompleted {
                    stage: "operation_admission",
                    stage_execution_id: format!("stg_{}", Uuid::now_v7()),
                    outcome,
                    reason_code: facts.decision.reason_code.as_str(),
                    proof_kind: "deterministic",
                    confidence: None,
                    confidence_status: "not_applicable",
                    duration_us: facts.duration_us,
                    rule_revision: Some(self.policy_revision.clone()),
                    model_call_id: None,
                    facts: StageFacts {
                        operation_id: operation_id.clone(),
                    },
                    coverage: StageCoverage {
                        admission_checked: true,
                    },
                },
            ),
        ];
        let mut last_stage_id = stage_id.as_str().to_owned();
        let mut request_sequence = 3;
        if let Some(crypto) = facts.request_crypto {
            let crypto_id = new_event_id()?;
            events.push(PendingEvent::new(
                crypto_id.clone(),
                "stage.completed",
                request_sequence,
                vec![last_stage_id],
                Payload::CryptoStageCompleted {
                    stage: "crypto_decode",
                    stage_execution_id: format!("stg_{}", Uuid::now_v7()),
                    outcome: crypto.outcome,
                    reason_code: crypto.reason_code.as_str(),
                    proof_kind: "deterministic",
                    confidence: None,
                    confidence_status: "not_applicable",
                    duration_us: crypto.duration_us,
                    rule_revision: Some(crypto.adapter_revision.clone()),
                    model_call_id: None,
                    facts: CryptoStageFacts {
                        operation_id: operation_id.clone(),
                        coverage_mode: crypto.coverage_mode,
                        algorithm: crypto.algorithm,
                        adapter_revision: crypto.adapter_revision.clone(),
                        key_id: crypto.key_id.clone(),
                        approval_ref: crypto.approval_ref.clone(),
                        source_evidence_ref: crypto.source_evidence_ref.clone(),
                        message_id: crypto.message_id.clone(),
                        nonce_sha256: crypto.nonce_sha256.clone(),
                        issued_at: crypto.issued_at,
                        expires_at: crypto.expires_at,
                        envelope_sha256: crypto.envelope_sha256.clone(),
                        rebuilt_sha256: crypto.rebuilt_sha256.clone(),
                    },
                    coverage: CryptoStageCoverage {
                        request_crypto_checked: crypto.coverage_mode == "ENFORCE",
                        origin_entity_rebuilt: crypto.rebuilt_sha256.is_some(),
                    },
                },
            ));
            last_stage_id = String::from(crypto_id.as_str());
            request_sequence += 1;
        }
        for observation in facts.sensor_observations {
            let observation_id = new_event_id()?;
            let previous_stage_id = last_stage_id;
            events.push(PendingEvent::new(
                observation_id.clone(),
                "sensor.observation",
                request_sequence,
                vec![previous_stage_id],
                Payload::SensorObservation {
                    binding_id: observation.binding_id.clone(),
                    auth_epoch: observation.auth_epoch,
                    authenticated: observation.authenticated,
                    build_ref: observation.build_ref.clone(),
                    page_handle: observation.page_handle.clone(),
                    navigation_id: observation.navigation_id.clone(),
                    action_hint: observation.action_hint.clone(),
                    client_request_id: observation.client_request_id.clone(),
                    client_event_seq: observation.client_event_seq,
                    visibility: observation.visibility,
                    sensor_event_type: observation.event_type,
                    callsite_fingerprint: observation.callsite_fingerprint.clone(),
                    claim_status: "client_claimed",
                    authorization_effect: "none",
                },
            ));
            last_stage_id = String::from(observation_id.as_str());
            request_sequence += 1;
        }
        if let Some(bootstrap) = facts.sensor_bootstrap {
            let bootstrap_id = new_event_id()?;
            let delivered = bootstrap.delivered > 0;
            events.push(PendingEvent::new(
                bootstrap_id.clone(),
                if delivered {
                    "stage.completed"
                } else {
                    "stage.skipped"
                },
                request_sequence,
                vec![last_stage_id],
                generic_stage(
                    "sensor_bootstrap",
                    if delivered { "PASS" } else { "SKIPPED" },
                    if delivered {
                        ReasonCode::SensorActionsDelivered
                    } else {
                        ReasonCode::SensorActionsUnavailable
                    },
                    Some(self.policy_revision.clone()),
                    operation_id.clone(),
                ),
            ));
            last_stage_id = String::from(bootstrap_id.as_str());
            request_sequence += 1;
        }
        events.push(PendingEvent::new(
            decision_id.clone(),
            "decision.composed",
            request_sequence,
            vec![last_stage_id],
            Payload::Decision {
                decision,
                reason_code: facts.decision.reason_code.as_str(),
                origin_state: "not_sent",
            },
        ));
        request_sequence += 1;
        let forward_intent_id =
            if facts.decision.outcome == GatewayOutcome::Allowed && facts.forward_origin {
                let event_id = new_event_id()?;
                events.push(PendingEvent::new(
                    event_id.clone(),
                    "origin.forward_intent",
                    request_sequence,
                    vec![decision_id.as_str().to_owned()],
                    Payload::Origin {
                        method: facts.method.to_owned(),
                        operation_id: facts
                            .decision
                            .operation_id
                            .as_ref()
                            .map(|operation| operation.as_str().to_owned()),
                        origin_state: "not_sent",
                        reason_code: ReasonCode::OriginForwardIntentRecorded.as_str(),
                        status: None,
                    },
                ));
                Some(event_id.as_str().to_owned())
            } else {
                None
            };
        let context = BatchContext {
            request_id: Some(facts.request_id.to_owned()),
            trace_id: facts.trace_id.to_owned(),
        };
        self.append(context, events).await?;
        Ok(AdmissionAudit {
            decision_event_id: decision_id.as_str().to_owned(),
            forward_intent_event_id: forward_intent_id,
            next_request_sequence: request_sequence
                + u32::from(
                    facts.decision.outcome == GatewayOutcome::Allowed && facts.forward_origin,
                ),
        })
    }

    pub(crate) async fn finalize(&self, facts: FinalFacts<'_>) -> Result<(), DurableAuditError> {
        let origin = final_origin(&facts);
        let mut events = Vec::new();
        let mut request_sequence = facts.admission.next_request_sequence;
        let mut completion_causes = vec![facts.admission.decision_event_id.clone()];
        if facts.decision.outcome == GatewayOutcome::Allowed {
            let delivery_id = new_event_id()?;
            events.push(delivery_event(
                &facts,
                &origin,
                delivery_id.clone(),
                request_sequence,
            ));
            completion_causes.push(delivery_id.as_str().to_owned());
            request_sequence = request_sequence
                .checked_add(1)
                .ok_or(DurableAuditError::SequenceExhausted)?;
        }
        let operation = facts
            .decision
            .operation_id
            .as_ref()
            .map(|operation| operation.as_str().to_owned());
        let mut chain = StageChain {
            events: &mut events,
            causes: &mut completion_causes,
            sequence: &mut request_sequence,
        };
        if let Some(crypto) = facts.response_crypto {
            chain.push(|sequence, causes| {
                response_crypto_event(crypto, operation.clone(), sequence, causes)
            })?;
        }
        if let Some(sensor_html) = facts.sensor_html {
            chain.push(|sequence, causes| {
                sensor_html_event(sensor_html, operation.clone(), sequence, causes)
            })?;
        }
        if let Some(page) = facts.page_actions {
            chain.push(|sequence, causes| {
                page_action_event(page, operation.clone(), sequence, causes)
            })?;
        }
        let completion_id = new_event_id()?;
        events.push(PendingEvent::new(
            completion_id,
            if facts.proxy_error || facts.response_failure.is_some() {
                "request.aborted"
            } else {
                "request.completed"
            },
            request_sequence,
            completion_causes,
            Payload::RequestCompleted {
                decision: match facts.decision.outcome {
                    GatewayOutcome::Allowed => "ALLOW".to_owned(),
                    GatewayOutcome::Denied => "DENY".to_owned(),
                },
                reason_code: completion_reason(&facts).to_owned(),
                status: (facts.status != 0).then_some(facts.status),
                origin_state: match facts.response_source {
                    ResponseSource::Origin => origin.state.to_owned(),
                    ResponseSource::Edge => "not_sent".to_owned(),
                },
                duration_us: facts.duration_us,
            },
        ));
        self.append(
            BatchContext {
                request_id: Some(facts.request_id.to_owned()),
                trace_id: facts.trace_id.to_owned(),
            },
            events,
        )
        .await?;
        Ok(())
    }

    fn record_recovery(&self, recovery: RecoveryReport) -> Result<(), DurableAuditError> {
        let event = PendingEvent::new(
            new_event_id()?,
            "audit.recovered",
            1,
            Vec::new(),
            Payload::Recovery {
                recovered_records: recovery.recovered_records,
                truncated_bytes: recovery.truncated_bytes,
                reason_code: ReasonCode::AuditTailRecovered.as_str(),
            },
        );
        append_locked(
            &self.journal,
            &self.tenant_id,
            &self.site_id,
            &self.policy_revision,
            &self.producer_id,
            &BatchContext {
                request_id: None,
                trace_id: new_trace_id(),
            },
            &[event],
        )?;
        Ok(())
    }

    fn record_incomplete(&self, requests: Vec<IncompleteRequest>) -> Result<(), DurableAuditError> {
        for request in requests {
            let mut sequence = request
                .last_request_sequence
                .checked_add(1)
                .ok_or(DurableAuditError::SequenceExhausted)?;
            let mut events = Vec::new();
            let (event_type, completion_cause, reason_code, status, origin_state) =
                if let Some(origin) = request.origin {
                    let event_type = if origin.state == "response_received"
                        && origin.reason_code == ReasonCode::OriginResponseReceived.as_str()
                    {
                        "request.completed"
                    } else {
                        "request.aborted"
                    };
                    (
                        event_type,
                        origin.event_id,
                        origin.reason_code,
                        origin.status,
                        origin.state,
                    )
                } else if let Some(forward) = request.forward {
                    let unknown_id = new_event_id()?;
                    events.push(PendingEvent::new(
                        unknown_id.clone(),
                        "origin.unknown",
                        sequence,
                        vec![forward.event_id],
                        Payload::Origin {
                            method: forward.method,
                            operation_id: forward.operation_id,
                            origin_state: "unknown",
                            reason_code: ReasonCode::OriginOutcomeUnknown.as_str(),
                            status: None,
                        },
                    ));
                    sequence = sequence
                        .checked_add(1)
                        .ok_or(DurableAuditError::SequenceExhausted)?;
                    (
                        "request.aborted",
                        unknown_id.as_str().to_owned(),
                        ReasonCode::OriginOutcomeUnknown.as_str().to_owned(),
                        None,
                        "unknown".to_owned(),
                    )
                } else {
                    let reason_code = if request.decision.outcome == "DENY" {
                        request.decision.reason_code.clone()
                    } else {
                        ReasonCode::RequestIncomplete.as_str().to_owned()
                    };
                    (
                        "request.aborted",
                        request.decision.event_id.clone(),
                        reason_code,
                        None,
                        "not_sent".to_owned(),
                    )
                };
            events.push(PendingEvent::new(
                new_event_id()?,
                event_type,
                sequence,
                vec![completion_cause],
                Payload::RequestCompleted {
                    decision: request.decision.outcome,
                    reason_code,
                    status,
                    origin_state,
                    duration_us: 0,
                },
            ));
            append_locked(
                &self.journal,
                &self.tenant_id,
                &self.site_id,
                &request.policy_revision,
                &self.producer_id,
                &BatchContext {
                    request_id: Some(request.request_id),
                    trace_id: request.trace_id,
                },
                &events,
            )?;
        }
        Ok(())
    }

    pub(crate) async fn record_evidence_capture(
        &self,
        request_id: &str,
        trace_id: &str,
        admission: &AdmissionAudit,
        artifact_id: &str,
        catalog_event_id: &str,
        profile_revision: &str,
    ) -> Result<(), DurableAuditError> {
        let mut event = PendingEvent::new(
            new_event_id()?,
            "evidence.captured",
            admission.next_request_sequence,
            vec![catalog_event_id.to_owned()],
            Payload::EvidenceCaptured {
                stage: "evidence_capture",
                outcome: "PASS",
                reason_code: "EVIDENCE_CAPTURED",
                proof_kind: "deterministic",
                confidence: None,
                profile_revision: profile_revision.to_owned(),
            },
        );
        event.evidence_refs.push(artifact_id.to_owned());
        self.append(
            BatchContext {
                request_id: Some(request_id.to_owned()),
                trace_id: trace_id.to_owned(),
            },
            vec![event],
        )
        .await?;
        Ok(())
    }

    async fn append(
        &self,
        context: BatchContext,
        events: Vec<PendingEvent>,
    ) -> Result<Vec<JournalReceipt>, DurableAuditError> {
        if !self.is_ready() {
            return Err(DurableAuditError::Unavailable);
        }
        let journal = Arc::clone(&self.journal);
        let ready = Arc::clone(&self.ready);
        let tenant_id = self.tenant_id.clone();
        let site_id = self.site_id.clone();
        let policy_revision = self.policy_revision.clone();
        let producer_id = self.producer_id.clone();
        // ponytail: one writer preserves ordering; shard by producer only after measured contention.
        let result = tokio::task::spawn_blocking(move || {
            append_locked(
                &journal,
                &tenant_id,
                &site_id,
                &policy_revision,
                &producer_id,
                &context,
                &events,
            )
        })
        .await;
        match result {
            Ok(Ok(receipts)) => Ok(receipts),
            Ok(Err(error)) => {
                ready.store(false, Ordering::Release);
                Err(error)
            }
            Err(error) => {
                ready.store(false, Ordering::Release);
                Err(DurableAuditError::Join(error))
            }
        }
    }
}

fn delivery_event(
    facts: &FinalFacts<'_>,
    origin: &FinalOrigin,
    event_id: EventId,
    request_sequence: u32,
) -> PendingEvent {
    let edge_reason = edge_response_reason(facts);
    let operation_id = facts
        .decision
        .operation_id
        .as_ref()
        .map(|operation| operation.as_str().to_owned());
    match facts.response_source {
        ResponseSource::Origin => PendingEvent::new(
            event_id,
            origin.event_type,
            request_sequence,
            facts
                .admission
                .forward_intent_event_id
                .iter()
                .cloned()
                .collect(),
            Payload::Origin {
                method: facts.method.to_owned(),
                operation_id,
                origin_state: origin.state,
                reason_code: origin.reason_code,
                status: origin.status,
            },
        ),
        ResponseSource::Edge => PendingEvent::new(
            event_id,
            if facts.proxy_error {
                "edge.unknown"
            } else {
                "edge.response"
            },
            request_sequence,
            vec![facts.admission.decision_event_id.clone()],
            Payload::Edge {
                method: facts.method.to_owned(),
                operation_id,
                edge_state: if facts.proxy_error {
                    "unknown"
                } else {
                    "response_served"
                },
                reason_code: if facts.proxy_error {
                    ReasonCode::RequestIncomplete.as_str()
                } else {
                    edge_reason.as_str()
                },
                status: (facts.status != 0).then_some(facts.status),
            },
        ),
    }
}

fn response_crypto_event(
    crypto: &ResponseCryptoAudit,
    operation_id: Option<String>,
    request_sequence: u32,
    cause_event_ids: Vec<String>,
) -> Result<(EventId, PendingEvent), DurableAuditError> {
    let event_id = new_event_id()?;
    let event = PendingEvent::new(
        event_id.clone(),
        "stage.completed",
        request_sequence,
        cause_event_ids,
        Payload::ResponseCryptoStageCompleted {
            stage: "crypto_encode",
            stage_execution_id: format!("stg_{}", Uuid::now_v7()),
            outcome: crypto.outcome,
            reason_code: crypto.reason_code.as_str(),
            proof_kind: "deterministic",
            confidence: None,
            confidence_status: "not_applicable",
            duration_us: crypto.duration_us,
            rule_revision: Some(crypto.adapter_revision.clone()),
            model_call_id: None,
            facts: CryptoStageFacts {
                operation_id,
                coverage_mode: "ENFORCE",
                algorithm: Some(crypto.algorithm),
                adapter_revision: crypto.adapter_revision.clone(),
                key_id: Some(crypto.key_id.clone()),
                approval_ref: None,
                source_evidence_ref: None,
                message_id: crypto.message_id.clone(),
                nonce_sha256: crypto.nonce_sha256.clone(),
                issued_at: crypto.issued_at,
                expires_at: crypto.expires_at,
                envelope_sha256: crypto.envelope_sha256.clone(),
                rebuilt_sha256: crypto.origin_sha256.clone(),
            },
            coverage: ResponseCryptoStageCoverage {
                response_crypto_checked: true,
                client_entity_rebuilt: crypto.envelope_sha256.is_some(),
            },
        },
    );
    Ok((event_id, event))
}

/// Appends response-side stages so each is caused by every event before it
/// and takes the next request sequence.
struct StageChain<'a> {
    events: &'a mut Vec<PendingEvent>,
    causes: &'a mut Vec<String>,
    sequence: &'a mut u32,
}

impl StageChain<'_> {
    fn push(
        &mut self,
        build: impl FnOnce(u32, Vec<String>) -> Result<(EventId, PendingEvent), DurableAuditError>,
    ) -> Result<(), DurableAuditError> {
        let (event_id, event) = build(*self.sequence, self.causes.clone())?;
        self.events.push(event);
        self.causes.push(event_id.as_str().to_owned());
        *self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(DurableAuditError::SequenceExhausted)?;
        Ok(())
    }
}

fn page_action_event(
    page: &PageActionAudit,
    operation_id: Option<String>,
    request_sequence: u32,
    cause_event_ids: Vec<String>,
) -> Result<(EventId, PendingEvent), DurableAuditError> {
    let event_id = new_event_id()?;
    let event = PendingEvent::new(
        event_id.clone(),
        "stage.completed",
        request_sequence,
        cause_event_ids,
        generic_stage(
            "ui_action_issue",
            page.outcome,
            page.reason_code,
            Some(page.mapping_revision.clone()),
            operation_id,
        ),
    );
    Ok((event_id, event))
}

/// A deterministic stage in the generic journal shape (operation-only facts),
/// which the worker's journal publisher accepts without a dedicated parser.
fn generic_stage(
    stage: &'static str,
    outcome: &'static str,
    reason: ReasonCode,
    rule_revision: Option<String>,
    operation_id: Option<String>,
) -> Payload {
    Payload::StageCompleted {
        stage,
        stage_execution_id: format!("stg_{}", Uuid::now_v7()),
        outcome,
        reason_code: reason.as_str(),
        proof_kind: "deterministic",
        confidence: None,
        confidence_status: "not_applicable",
        duration_us: 0,
        rule_revision,
        model_call_id: None,
        facts: StageFacts { operation_id },
        coverage: StageCoverage {
            admission_checked: true,
        },
    }
}

fn sensor_html_event(
    sensor_html: &SensorHtmlAudit,
    operation_id: Option<String>,
    request_sequence: u32,
    cause_event_ids: Vec<String>,
) -> Result<(EventId, PendingEvent), DurableAuditError> {
    let event_id = new_event_id()?;
    let event = PendingEvent::new(
        event_id.clone(),
        "stage.completed",
        request_sequence,
        cause_event_ids,
        Payload::SensorHtmlStageCompleted {
            stage: "sensor_html_inject",
            stage_execution_id: format!("stg_{}", Uuid::now_v7()),
            outcome: "PASS",
            reason_code: ReasonCode::SensorHtmlInjected.as_str(),
            proof_kind: "deterministic",
            confidence: None,
            confidence_status: "not_applicable",
            duration_us: 0,
            rule_revision: Some(sensor_html.adapter_revision.clone()),
            model_call_id: None,
            facts: SensorHtmlStageFacts {
                operation_id,
                origin_sha256: sensor_html.origin_sha256.clone(),
                injected_sha256: sensor_html.injected_sha256.clone(),
                csp_nonce_applied: sensor_html.csp_nonce_applied,
            },
            coverage: SensorHtmlStageCoverage {
                origin_entity_verified: true,
                sensor_scripts_injected: true,
            },
        },
    );
    Ok((event_id, event))
}

fn final_origin(facts: &FinalFacts<'_>) -> FinalOrigin {
    if facts.decision.outcome == GatewayOutcome::Denied {
        return FinalOrigin {
            state: "not_sent",
            event_type: "origin.unknown",
            reason_code: facts.decision.reason_code.as_str(),
            status: None,
        };
    }
    if let Some(reason) = facts.response_failure {
        return FinalOrigin {
            state: "response_received",
            event_type: "origin.response",
            reason_code: reason.as_str(),
            status: facts.origin_status,
        };
    }
    if facts.proxy_error
        && facts.origin_response_complete
        && let Some(status) = facts.origin_status
    {
        // A downstream failure cannot erase the fully received origin response.
        // The request terminal separately records incomplete client delivery.
        return FinalOrigin {
            state: "response_received",
            event_type: "origin.response",
            reason_code: ReasonCode::OriginResponseReceived.as_str(),
            status: Some(status),
        };
    }
    if facts.proxy_error {
        FinalOrigin {
            state: "unknown",
            event_type: "origin.unknown",
            reason_code: ReasonCode::OriginOutcomeUnknown.as_str(),
            status: None,
        }
    } else {
        FinalOrigin {
            state: "response_received",
            event_type: "origin.response",
            reason_code: ReasonCode::OriginResponseReceived.as_str(),
            status: Some(facts.status),
        }
    }
}

fn completion_reason(facts: &FinalFacts<'_>) -> &'static str {
    if facts.response_source == ResponseSource::Edge {
        return facts.response_failure.map_or_else(
            || {
                if facts.proxy_error {
                    ReasonCode::RequestIncomplete.as_str()
                } else {
                    edge_response_reason(facts).as_str()
                }
            },
            ReasonCode::as_str,
        );
    }
    facts.response_failure.map_or_else(
        || {
            if facts.decision.outcome == GatewayOutcome::Denied {
                facts.decision.reason_code.as_str()
            } else if facts.proxy_error
                && facts.origin_response_complete
                && facts.origin_status.is_some()
            {
                ReasonCode::RequestIncomplete.as_str()
            } else if facts.proxy_error {
                ReasonCode::OriginOutcomeUnknown.as_str()
            } else {
                ReasonCode::OriginResponseReceived.as_str()
            }
        },
        ReasonCode::as_str,
    )
}

fn edge_response_reason(facts: &FinalFacts<'_>) -> ReasonCode {
    let operation = facts
        .decision
        .operation_id
        .as_ref()
        .map(xshield_core::domain::OperationId::as_str);
    match operation {
        Some("xshield.sensor.bootstrap") => ReasonCode::SensorBootstrapServed,
        Some("xshield.sensor.loader" | "xshield.sensor.legacy_loader") => {
            ReasonCode::SensorLoaderServed
        }
        Some("xshield.sensor.prepare") => ReasonCode::SensorObservationAccepted,
        _ => ReasonCode::SensorAssetServed,
    }
}

/// Bytes held by journal segments in `directory`: the same quantity the
/// journal counts against its quota, read from disk without opening it.
fn segment_bytes_on_disk(directory: &Path) -> Result<u64, DurableAuditError> {
    let mut total = 0_u64;
    for entry in std::fs::read_dir(directory).map_err(JournalError::Io)? {
        let entry = entry.map_err(JournalError::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("segment-")
            && Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "xja")
        {
            total = total.saturating_add(entry.metadata().map_err(JournalError::Io)?.len());
        }
    }
    Ok(total)
}

fn reopen_blocking(
    journal: &Arc<Mutex<Option<LocalJournal>>>,
    source: &ReopenSource,
    scope: (&str, &str, &str, &str),
) -> Result<(), DurableAuditError> {
    if segment_bytes_on_disk(&source.directory)? >= source.high_watermark_bytes {
        return Err(DurableAuditError::Unavailable);
    }
    // A poisoned mutex only means a writer panicked mid-append; the handle is
    // discarded below, so its contents no longer matter.
    let mut slot = journal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Release the failed writer (and its single-writer lock) before reopening.
    drop(slot.take());
    let (mut opened, report) = LocalJournal::open(
        &source.directory,
        &source.key_id,
        JournalKey::from_hex(&source.key_hex)?,
        source.limits,
    )?;
    if opened.status().high_watermark_reached {
        // Raced with new writes; keep the healthy handle but stay closed.
        *slot = Some(opened);
        return Err(DurableAuditError::Unavailable);
    }
    let event = PendingEvent::new(
        new_event_id()?,
        "audit.recovered",
        1,
        Vec::new(),
        Payload::Recovery {
            recovered_records: report.recovered_records,
            truncated_bytes: report.truncated_bytes,
            reason_code: ReasonCode::AuditBarrierReopened.as_str(),
        },
    );
    let appended = append_events(
        &mut opened,
        scope.0,
        scope.1,
        scope.2,
        scope.3,
        &BatchContext {
            request_id: None,
            trace_id: new_trace_id(),
        },
        &[event],
    );
    *slot = Some(opened);
    appended.map(|_| ())
}

/// Bounded exponential backoff between reopen attempts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecoveryBackoff {
    initial: Duration,
    max: Duration,
}

impl RecoveryBackoff {
    pub(crate) const PRODUCTION: Self = Self {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(30),
    };

    fn next(self, current: Duration) -> Duration {
        current.saturating_mul(2).min(self.max)
    }
}

/// Keeps the admission barrier recoverable: while it is closed, retries
/// [`DurableAudit::try_reopen`] with bounded backoff until it succeeds or the
/// process shuts down. While it is open this only polls an atomic flag.
pub(crate) async fn supervise_recovery(
    audit: DurableAudit,
    backoff: RecoveryBackoff,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut delay = backoff.initial;
    loop {
        let wait = if audit.is_ready() {
            delay = backoff.initial;
            backoff.initial
        } else {
            delay
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
        if audit.is_ready() {
            continue;
        }
        delay = if audit.try_reopen().await.is_ok() {
            backoff.initial
        } else {
            backoff.next(delay)
        };
    }
}

fn append_locked(
    journal: &Arc<Mutex<Option<LocalJournal>>>,
    tenant_id: &str,
    site_id: &str,
    policy_revision: &str,
    producer_id: &str,
    context: &BatchContext,
    events: &[PendingEvent],
) -> Result<Vec<JournalReceipt>, DurableAuditError> {
    let mut slot = journal
        .lock()
        .map_err(|_| DurableAuditError::LockPoisoned)?;
    let journal = slot.as_mut().ok_or(DurableAuditError::Unavailable)?;
    append_events(
        journal,
        tenant_id,
        site_id,
        policy_revision,
        producer_id,
        context,
        events,
    )
}

fn append_events(
    journal: &mut LocalJournal,
    tenant_id: &str,
    site_id: &str,
    policy_revision: &str,
    producer_id: &str,
    context: &BatchContext,
    events: &[PendingEvent],
) -> Result<Vec<JournalReceipt>, DurableAuditError> {
    let first_sequence = journal
        .next_sequence()
        .ok_or(DurableAuditError::SequenceExhausted)?;
    let producer_boot_id = journal.producer_boot_id();
    let encoding = EncodingContext {
        tenant_id,
        site_id,
        policy_revision,
        producer_id,
        producer_boot_id: &producer_boot_id,
        batch: context,
    };
    let mut encoded = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let offset = u64::try_from(index).map_err(|_| DurableAuditError::SequenceExhausted)?;
        let producer_sequence = first_sequence
            .checked_add(offset)
            .ok_or(DurableAuditError::SequenceExhausted)?;
        encoded.push(encode_event(&encoding, producer_sequence, event)?);
    }
    let records = events
        .iter()
        .zip(&encoded)
        .map(|(event, plaintext)| JournalRecord {
            event_id: &event.event_id,
            plaintext,
        })
        .collect::<Vec<_>>();
    let receipts = journal.append_batch(&records)?;
    let receipts_match = receipts.len() == events.len()
        && receipts.iter().enumerate().all(|(index, receipt)| {
            u64::try_from(index)
                .ok()
                .and_then(|offset| first_sequence.checked_add(offset))
                == Some(receipt.producer_sequence)
        });
    if !receipts_match {
        return Err(DurableAuditError::ReceiptMismatch);
    }
    Ok(receipts)
}

fn encode_event(
    context: &EncodingContext<'_>,
    producer_sequence: u64,
    event: &PendingEvent,
) -> Result<Vec<u8>, DurableAuditError> {
    let wire = WireAuditEvent {
        schema_version: 3,
        event_id: event.event_id.as_str(),
        event_type: event.event_type,
        tenant_id: context.tenant_id,
        site_id: context.site_id,
        request_id: context.batch.request_id.as_deref(),
        trace_id: &context.batch.trace_id,
        span_id: &event.span_id,
        producer_id: context.producer_id,
        producer_boot_id: context.producer_boot_id,
        producer_seq: producer_sequence,
        request_seq: event.request_sequence,
        occurred_at: &event.occurred_at,
        observed_at: &event.occurred_at,
        policy_revision: context.policy_revision,
        example_only: false,
        evidence_refs: &event.evidence_refs,
        cause_event_ids: &event.cause_event_ids,
        payload: &event.payload,
        sensitivity: "INTERNAL",
        integrity: Integrity {
            state: "pending",
            previous_hash: None,
            event_hash: None,
        },
    };
    Ok(serde_json::to_vec(&wire)?)
}

fn new_event_id() -> Result<EventId, DurableAuditError> {
    EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(DurableAuditError::InvalidId)
}

fn operation_id(decision: &GatewayDecision) -> Option<String> {
    decision
        .operation_id
        .as_ref()
        .map(|operation| operation.as_str().to_owned())
}

const fn stage_outcome(outcome: GatewayOutcome) -> &'static str {
    match outcome {
        GatewayOutcome::Allowed => "PASS",
        GatewayOutcome::Denied => "DENY",
    }
}

const fn decision_name(outcome: GatewayOutcome) -> &'static str {
    match outcome {
        GatewayOutcome::Allowed => "ALLOW",
        GatewayOutcome::Denied => "DENY",
    }
}

pub(crate) fn new_trace_id() -> String {
    Uuid::now_v7().simple().to_string()
}

fn new_span_id() -> String {
    Uuid::now_v7()
        .simple()
        .to_string()
        .chars()
        .take(16)
        .collect()
}

struct BatchContext {
    request_id: Option<String>,
    trace_id: String,
}

struct EncodingContext<'a> {
    tenant_id: &'a str,
    site_id: &'a str,
    policy_revision: &'a str,
    producer_id: &'a str,
    producer_boot_id: &'a str,
    batch: &'a BatchContext,
}

struct PendingEvent {
    event_id: EventId,
    event_type: &'static str,
    request_sequence: u32,
    occurred_at: String,
    span_id: String,
    cause_event_ids: Vec<String>,
    evidence_refs: Vec<String>,
    payload: Payload,
}

impl PendingEvent {
    fn new(
        event_id: EventId,
        event_type: &'static str,
        request_sequence: u32,
        cause_event_ids: Vec<String>,
        payload: Payload,
    ) -> Self {
        Self {
            event_id,
            event_type,
            request_sequence,
            occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            span_id: new_span_id(),
            cause_event_ids,
            evidence_refs: Vec::new(),
            payload,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Payload {
    EvidenceCaptured {
        stage: &'static str,
        outcome: &'static str,
        reason_code: &'static str,
        proof_kind: &'static str,
        confidence: Option<f64>,
        profile_revision: String,
    },
    RequestAccepted {
        method: String,
        operation_id: Option<String>,
        origin_state: &'static str,
    },
    StageCompleted {
        stage: &'static str,
        stage_execution_id: String,
        outcome: &'static str,
        reason_code: &'static str,
        proof_kind: &'static str,
        confidence: Option<f64>,
        confidence_status: &'static str,
        duration_us: u64,
        rule_revision: Option<String>,
        model_call_id: Option<String>,
        facts: StageFacts,
        coverage: StageCoverage,
    },
    CryptoStageCompleted {
        stage: &'static str,
        stage_execution_id: String,
        outcome: &'static str,
        reason_code: &'static str,
        proof_kind: &'static str,
        confidence: Option<f64>,
        confidence_status: &'static str,
        duration_us: u64,
        rule_revision: Option<String>,
        model_call_id: Option<String>,
        facts: CryptoStageFacts,
        coverage: CryptoStageCoverage,
    },
    ResponseCryptoStageCompleted {
        stage: &'static str,
        stage_execution_id: String,
        outcome: &'static str,
        reason_code: &'static str,
        proof_kind: &'static str,
        confidence: Option<f64>,
        confidence_status: &'static str,
        duration_us: u64,
        rule_revision: Option<String>,
        model_call_id: Option<String>,
        facts: CryptoStageFacts,
        coverage: ResponseCryptoStageCoverage,
    },
    Decision {
        decision: &'static str,
        reason_code: &'static str,
        origin_state: &'static str,
    },
    Origin {
        method: String,
        operation_id: Option<String>,
        origin_state: &'static str,
        reason_code: &'static str,
        status: Option<u16>,
    },
    Edge {
        method: String,
        operation_id: Option<String>,
        edge_state: &'static str,
        reason_code: &'static str,
        status: Option<u16>,
    },
    SensorObservation {
        binding_id: String,
        auth_epoch: u64,
        authenticated: bool,
        build_ref: String,
        page_handle: String,
        navigation_id: String,
        action_hint: Option<String>,
        client_request_id: Option<String>,
        client_event_seq: u32,
        visibility: &'static str,
        sensor_event_type: &'static str,
        callsite_fingerprint: Option<String>,
        claim_status: &'static str,
        authorization_effect: &'static str,
    },
    SensorHtmlStageCompleted {
        stage: &'static str,
        stage_execution_id: String,
        outcome: &'static str,
        reason_code: &'static str,
        proof_kind: &'static str,
        confidence: Option<f64>,
        confidence_status: &'static str,
        duration_us: u64,
        rule_revision: Option<String>,
        model_call_id: Option<String>,
        facts: SensorHtmlStageFacts,
        coverage: SensorHtmlStageCoverage,
    },
    RequestCompleted {
        decision: String,
        reason_code: String,
        status: Option<u16>,
        origin_state: String,
        duration_us: u64,
    },
    Recovery {
        recovered_records: u64,
        truncated_bytes: u64,
        reason_code: &'static str,
    },
    Unrouted {
        listener_port: u16,
        denied_count: u64,
        first_seen_unix: u64,
        last_seen_unix: u64,
        sample_host: Option<String>,
        reason_code: &'static str,
    },
}

#[derive(Serialize)]
struct SensorHtmlStageFacts {
    operation_id: Option<String>,
    origin_sha256: String,
    injected_sha256: String,
    csp_nonce_applied: bool,
}

#[derive(Serialize)]
struct SensorHtmlStageCoverage {
    origin_entity_verified: bool,
    sensor_scripts_injected: bool,
}

#[derive(Serialize)]
struct StageFacts {
    operation_id: Option<String>,
}

#[derive(Serialize)]
struct StageCoverage {
    admission_checked: bool,
}

#[derive(Serialize)]
struct CryptoStageFacts {
    operation_id: Option<String>,
    coverage_mode: &'static str,
    algorithm: Option<&'static str>,
    adapter_revision: String,
    key_id: Option<String>,
    approval_ref: Option<String>,
    source_evidence_ref: Option<String>,
    message_id: Option<String>,
    nonce_sha256: Option<String>,
    issued_at: Option<u64>,
    expires_at: Option<u64>,
    envelope_sha256: Option<String>,
    rebuilt_sha256: Option<String>,
}

#[derive(Serialize)]
struct CryptoStageCoverage {
    request_crypto_checked: bool,
    origin_entity_rebuilt: bool,
}

#[derive(Serialize)]
struct ResponseCryptoStageCoverage {
    response_crypto_checked: bool,
    client_entity_rebuilt: bool,
}

#[derive(Serialize)]
struct Integrity<'a> {
    state: &'a str,
    previous_hash: Option<&'a str>,
    event_hash: Option<&'a str>,
}

#[derive(Serialize)]
struct WireAuditEvent<'a> {
    schema_version: u8,
    event_id: &'a str,
    event_type: &'a str,
    tenant_id: &'a str,
    site_id: &'a str,
    request_id: Option<&'a str>,
    trace_id: &'a str,
    span_id: &'a str,
    producer_id: &'a str,
    producer_boot_id: &'a str,
    producer_seq: u64,
    request_seq: u32,
    occurred_at: &'a str,
    observed_at: &'a str,
    policy_revision: &'a str,
    example_only: bool,
    evidence_refs: &'a [String],
    cause_event_ids: &'a [String],
    payload: &'a Payload,
    sensitivity: &'a str,
    integrity: Integrity<'a>,
}

#[derive(Debug)]
pub(crate) enum DurableAuditError {
    Journal(JournalError),
    Json(serde_json::Error),
    Join(JoinError),
    InvalidId(InvalidValue),
    LockPoisoned,
    SequenceExhausted,
    ReceiptMismatch,
    Unavailable,
    InvalidHistoricalEvent,
}

impl fmt::Display for DurableAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => error.fmt(formatter),
            Self::Json(_) => formatter.write_str("audit event serialization failed"),
            Self::Join(_) => formatter.write_str("audit blocking task failed"),
            Self::InvalidId(error) => error.fmt(formatter),
            Self::LockPoisoned => formatter.write_str("audit writer lock poisoned"),
            Self::SequenceExhausted => formatter.write_str("audit sequence exhausted"),
            Self::ReceiptMismatch => formatter.write_str("audit receipt sequence mismatch"),
            Self::Unavailable => formatter.write_str("audit durability unavailable"),
            Self::InvalidHistoricalEvent => {
                formatter.write_str("historical audit event is invalid")
            }
        }
    }
}

impl std::error::Error for DurableAuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Join(error) => Some(error),
            Self::InvalidId(error) => Some(error),
            Self::LockPoisoned
            | Self::SequenceExhausted
            | Self::ReceiptMismatch
            | Self::Unavailable
            | Self::InvalidHistoricalEvent => None,
        }
    }
}

impl From<JournalError> for DurableAuditError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<serde_json::Error> for DurableAuditError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use xshield_core::identity::UnixSeconds;
    use xshield_gateway::{
        SENSOR_ASSET_PATH, SENSOR_BOOTSTRAP_PATH, SENSOR_LOADER_PATH, SENSOR_PREPARE_PATH,
        request_crypto::RequestCryptoPolicy,
    };

    const KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!("xshield-gateway-audit-{}", Uuid::now_v7()))
    }

    fn config(directory: &std::path::Path, max_bytes: u64) -> GatewayConfig {
        config_segmented(directory, max_bytes, max_bytes)
    }

    // Small segments rotate often, leaving closed segments an operator or the
    // publisher can later remove to free quota.
    #[allow(clippy::too_many_lines)]
    fn config_segmented(
        directory: &std::path::Path,
        max_bytes: u64,
        segment_bytes: u64,
    ) -> GatewayConfig {
        let json = serde_json::json!({
            "listen": "127.0.0.1:6188",
            "origin": {
                "address": "127.0.0.1:8080",
                "server_name": "origin.example",
                "tls": false
            },
            "tenant_id": "tenant_test",
            "site_id": "site_test",
            "policy_revision": "policy-r1",
            "audit": {
                "directory": directory,
                "key_id": "journal-key-r1",
                "producer_id": "edge-test",
                "max_bytes": max_bytes,
                "high_watermark_bytes": max_bytes / 2,
                "segment_max_bytes": segment_bytes
            },
            "identity_store": {
                "max_connections": 2,
                "acquire_timeout_ms": 1000
            },
            "sensor": {
                "origin": "https://app.example",
                "build_ref": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "heartbeat_seconds": 15
            },
            "operations": [
                {
                    "operation_id": "health.read",
                    "method": "GET",
                    "path": "/health",
                    "admission": "PUBLIC",
                    "source_action": null,
                    "resource_type": null,
                    "view_profile": null,
                    "response": {
                        "mode": "BUFFERED_JSON",
                        "max_bytes": 1024,
                        "crypto": {
                            "mode": "DIRECT_ENCRYPT",
                            "adapter_revision": "health-response-r1",
                            "key_id": "response-key-r1",
                            "key_not_before": 1,
                            "key_expires_at": 4_102_444_800_u64,
                            "message_ttl_seconds": 60,
                            "max_envelope_bytes": 3072
                        }
                    }
                },
                {
                    "operation_id": "orders.create",
                    "method": "POST",
                    "path": "/orders",
                    "admission": "PUBLIC",
                    "source_action": null,
                    "resource_type": null,
                    "view_profile": null,
                    "request_crypto": {
                        "mode": "DIRECT_DECRYPT",
                        "adapter_revision": "orders-json-r1",
                        "key_id": "request-key-r1",
                        "key_not_before": 1,
                        "key_expires_at": 4_102_444_800_u64,
                        "max_envelope_bytes": 4096,
                        "max_plaintext_bytes": 1024,
                        "max_message_age_seconds": 60,
                        "max_future_skew_seconds": 5,
                        "max_active_messages": 1000
                    }
                },
                {
                    "operation_id": "orders.observe",
                    "method": "POST",
                    "path": "/orders-observe",
                    "admission": "PUBLIC",
                    "source_action": null,
                    "resource_type": null,
                    "view_profile": null,
                    "request_crypto": {
                        "mode": "OBSERVE",
                        "adapter_revision": "orders-candidate-r2"
                    }
                },
                {
                    "operation_id": "orders.compatibility",
                    "method": "POST",
                    "path": "/orders-legacy",
                    "admission": "UI_ACTION_REQUIRED",
                    "source_action": "orders.legacy.submit",
                    "resource_type": null,
                    "view_profile": null,
                    "request_crypto": {
                        "mode": "COMPATIBILITY",
                        "adapter_revision": "orders-legacy-r1",
                        "approval_ref": "approval-42",
                        "expires_at": 4_102_444_800_u64,
                        "build_fingerprints": [
                            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        ]
                    }
                },
                {
                    "operation_id": "home.read",
                    "method": "GET",
                    "path": "/home",
                    "admission": "PUBLIC",
                    "source_action": null,
                    "resource_type": null,
                    "view_profile": null,
                    "response": {
                        "mode": "SENSOR_HTML",
                        "max_bytes": 128,
                        "adapter_revision": "home-r1",
                        "origin_sha256": "8afe2e0204ebb1d838fdd6ce33cfb526ad18ca0d3877cc1a3768a778332c054a",
                        "injection_offset": 27
                    }
                }
            ]
        });
        GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn records_exact_sensor_html_transformation() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000028";
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("GET", "/home", UnixSeconds::new(1));
        let admission = audit
            .commit_admission(AdmissionFacts {
                request_id,
                trace_id: "28282828282828282828282828282828",
                method: "GET",
                decision: &decision,
                duration_us: 10,
                request_crypto: None,
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        let transformation = SensorHtmlAudit::new(
            "home-r1".to_owned(),
            "8afe2e0204ebb1d838fdd6ce33cfb526ad18ca0d3877cc1a3768a778332c054a".to_owned(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            false,
        );
        audit
            .finalize(FinalFacts {
                request_id,
                trace_id: "28282828282828282828282828282828",
                method: "GET",
                decision: &decision,
                admission: &admission,
                status: 200,
                duration_us: 20,
                proxy_error: false,
                response_failure: None,
                origin_status: Some(200),
                origin_response_complete: true,
                response_crypto: None,
                sensor_html: Some(&transformation),
                page_actions: None,
                response_source: ResponseSource::Origin,
            })
            .await
            .unwrap();
        drop(audit);

        let (journal, _) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut stage = None;
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["request_id"] == request_id
                    && event["payload"]["stage"] == "sensor_html_inject"
                {
                    stage = Some(event);
                }
                Ok(())
            })
            .unwrap();
        let stage = stage.unwrap();
        assert_eq!(stage["payload"]["reason_code"], "SENSOR_HTML_INJECTED");
        assert_eq!(stage["payload"]["rule_revision"], "home-r1");
        assert_eq!(stage["payload"]["facts"]["csp_nonce_applied"], false);
        assert_eq!(stage["payload"]["confidence"], serde_json::Value::Null);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One journal round trip per outcome keeps the matrix readable.
    async fn records_bootstrap_delivery_and_page_issuance_in_the_generic_stage_shape() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("GET", "/home", UnixSeconds::new(1));
        let cases = [
            ("req_018f2a3b-4c5d-7000-8000-000000000031", Some(2), None),
            ("req_018f2a3b-4c5d-7000-8000-000000000032", Some(0), None),
            (
                "req_018f2a3b-4c5d-7000-8000-000000000033",
                None,
                Some(PageActionAudit::issued(
                    ReasonCode::UiActionIssued,
                    "mapping-r1",
                )),
            ),
            (
                "req_018f2a3b-4c5d-7000-8000-000000000034",
                None,
                Some(PageActionAudit::failed(
                    ReasonCode::UiActionCapacityExceeded,
                    "mapping-r1",
                )),
            ),
            (
                "req_018f2a3b-4c5d-7000-8000-000000000035",
                None,
                Some(PageActionAudit::failed(
                    ReasonCode::IdentityStoreUnavailable,
                    "mapping-r1",
                )),
            ),
        ];
        for (request_id, delivered, page) in &cases {
            let bootstrap = delivered.map(SensorBootstrapAudit::new);
            let admission = audit
                .commit_admission(AdmissionFacts {
                    request_id,
                    trace_id: "31313131313131313131313131313131",
                    method: "GET",
                    decision: &decision,
                    duration_us: 10,
                    request_crypto: None,
                    sensor_observations: &[],
                    sensor_bootstrap: bootstrap.as_ref(),
                    forward_origin: true,
                })
                .await
                .unwrap();
            audit
                .finalize(FinalFacts {
                    request_id,
                    trace_id: "31313131313131313131313131313131",
                    method: "GET",
                    decision: &decision,
                    admission: &admission,
                    status: 200,
                    duration_us: 20,
                    proxy_error: false,
                    response_failure: None,
                    origin_status: Some(200),
                    origin_response_complete: true,
                    response_crypto: None,
                    sensor_html: None,
                    page_actions: page.as_ref(),
                    response_source: ResponseSource::Origin,
                })
                .await
                .unwrap();
        }
        drop(audit);
        let (journal, _) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut stages = Vec::new();
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if matches!(
                    event["payload"]["stage"].as_str(),
                    Some("sensor_bootstrap" | "ui_action_issue")
                ) {
                    stages.push(event);
                }
                Ok(())
            })
            .unwrap();
        let summary = stages
            .iter()
            .map(|event| {
                // Only the generic facts/coverage shape: the worker journal
                // publisher rejects unknown stage members.
                assert_eq!(
                    event["payload"]["facts"].as_object().unwrap().len(),
                    1,
                    "{event}"
                );
                assert_eq!(
                    event["payload"]["coverage"],
                    serde_json::json!({"admission_checked": true})
                );
                assert_eq!(event["payload"]["confidence"], serde_json::Value::Null);
                (
                    event["event_type"].as_str().unwrap().to_owned(),
                    event["payload"]["outcome"].as_str().unwrap().to_owned(),
                    event["payload"]["reason_code"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        let expected = [
            ("stage.completed", "PASS", "SENSOR_ACTIONS_DELIVERED"),
            ("stage.skipped", "SKIPPED", "SENSOR_ACTIONS_UNAVAILABLE"),
            ("stage.completed", "PASS", "UI_ACTION_ISSUED"),
            ("stage.completed", "DENY", "UI_ACTION_CAPACITY_EXCEEDED"),
            ("stage.completed", "ERROR", "IDENTITY_STORE_UNAVAILABLE"),
        ]
        .map(|(event, outcome, reason)| (event.to_owned(), outcome.to_owned(), reason.to_owned()));
        assert_eq!(summary, expected);
        assert!(
            stages[2..]
                .iter()
                .all(|event| event["payload"]["rule_revision"] == "mapping-r1")
        );
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    fn append_accepted_prefix(
        config: &GatewayConfig,
        directory: &std::path::Path,
        tenant_id: &str,
        request_id: &str,
        trace_id: &str,
    ) {
        let (mut journal, _) = LocalJournal::open(
            directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": 3,
            "event_id": event_id.as_str(),
            "event_type": "request.accepted",
            "tenant_id": tenant_id,
            "site_id": "site_test",
            "request_id": request_id,
            "trace_id": trace_id,
            "span_id": &trace_id[..16],
            "producer_id": "edge-test",
            "producer_boot_id": journal.producer_boot_id(),
            "producer_seq": 1,
            "request_seq": 1,
            "occurred_at": "2026-09-18T00:00:00.000Z",
            "observed_at": "2026-09-18T00:00:00.000Z",
            "policy_revision": "policy-r1",
            "example_only": false,
            "evidence_refs": [],
            "cause_event_ids": [],
            "payload": {"method": "GET", "operation_id": "health.read", "origin_state": "not_sent"},
            "sensitivity": "INTERNAL",
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
        }))
        .unwrap();
        journal
            .append_batch(&[JournalRecord {
                event_id: &event_id,
                plaintext: &bytes,
            }])
            .unwrap();
    }

    #[tokio::test]
    async fn persists_admission_barrier_and_terminal_events() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("GET", "/health", UnixSeconds::new(1));
        let admission = audit
            .commit_admission(AdmissionFacts {
                request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
                trace_id: "11111111111111111111111111111111",
                method: "GET",
                decision: &decision,
                duration_us: 10,
                request_crypto: None,
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        assert!(admission.forward_intent_event_id.is_some());
        audit
            .finalize(FinalFacts {
                request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
                trace_id: "11111111111111111111111111111111",
                method: "GET",
                decision: &decision,
                admission: &admission,
                status: 200,
                duration_us: 20,
                proxy_error: false,
                response_failure: None,
                origin_status: Some(200),
                origin_response_complete: true,
                response_crypto: None,
                sensor_html: None,
                page_actions: None,
                response_source: ResponseSource::Origin,
            })
            .await
            .unwrap();
        let denied = config.admit("GET", "/unknown", UnixSeconds::new(1));
        let denied_admission = audit
            .commit_admission(AdmissionFacts {
                request_id: "req_018f2a3b-4c5d-7000-8000-000000000003",
                trace_id: "33333333333333333333333333333333",
                method: "GET",
                decision: &denied,
                duration_us: 10,
                request_crypto: None,
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        assert!(denied_admission.forward_intent_event_id.is_none());
        audit
            .finalize(FinalFacts {
                request_id: "req_018f2a3b-4c5d-7000-8000-000000000003",
                trace_id: "33333333333333333333333333333333",
                method: "GET",
                decision: &denied,
                admission: &denied_admission,
                status: 403,
                duration_us: 20,
                proxy_error: false,
                response_failure: None,
                origin_status: None,
                origin_response_complete: false,
                response_crypto: None,
                sensor_html: None,
                page_actions: None,
                response_source: ResponseSource::Origin,
            })
            .await
            .unwrap();
        drop(audit);

        let (journal, report) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        assert_eq!(report.recovered_records, 10);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn records_edge_sensor_deliveries_without_origin_intent() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let observation = SensorObservationAudit {
            binding_id: "auth_018f2a3b-4c5d-7000-8000-000000000023".to_owned(),
            auth_epoch: 1,
            authenticated: true,
            build_ref: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            page_handle: "pgh_018f2a3b-4c5d-7000-8000-000000000024".to_owned(),
            navigation_id: "nav_018f2a3b-4c5d-7000-8000-000000000025".to_owned(),
            action_hint: None,
            client_request_id: None,
            client_event_seq: 1,
            visibility: "visible",
            event_type: "PAGE_READY",
            callsite_fingerprint: None,
        };
        let cases = [
            (
                "GET",
                SENSOR_ASSET_PATH,
                "req_018f2a3b-4c5d-7000-8000-000000000021",
                ReasonCode::SensorAssetServed,
                4,
            ),
            (
                "GET",
                SENSOR_BOOTSTRAP_PATH,
                "req_018f2a3b-4c5d-7000-8000-000000000022",
                ReasonCode::SensorBootstrapServed,
                4,
            ),
            (
                "GET",
                SENSOR_LOADER_PATH,
                "req_018f2a3b-4c5d-7000-8000-000000000027",
                ReasonCode::SensorLoaderServed,
                4,
            ),
            (
                "POST",
                SENSOR_PREPARE_PATH,
                "req_018f2a3b-4c5d-7000-8000-000000000026",
                ReasonCode::SensorObservationAccepted,
                5,
            ),
        ];
        for &(method, path, request_id, _, _) in &cases {
            let decision = if path == SENSOR_PREPARE_PATH {
                config.admit_sensor_session(method, path)
            } else {
                config.admit(method, path, UnixSeconds::new(1))
            };
            let sensor_observations = if path == SENSOR_PREPARE_PATH {
                std::slice::from_ref(&observation)
            } else {
                &[]
            };
            let admission = audit
                .commit_admission(AdmissionFacts {
                    request_id,
                    trace_id: "21212121212121212121212121212121",
                    method,
                    decision: &decision,
                    duration_us: 10,
                    request_crypto: None,
                    sensor_observations,
                    sensor_bootstrap: None,
                    forward_origin: false,
                })
                .await
                .unwrap();
            assert!(admission.forward_intent_event_id.is_none());
            audit
                .finalize(FinalFacts {
                    request_id,
                    trace_id: "21212121212121212121212121212121",
                    method,
                    decision: &decision,
                    admission: &admission,
                    status: 200,
                    duration_us: 20,
                    proxy_error: false,
                    response_failure: None,
                    origin_status: None,
                    origin_response_complete: false,
                    response_crypto: None,
                    sensor_html: None,
                    page_actions: None,
                    response_source: ResponseSource::Edge,
                })
                .await
                .unwrap();
        }
        drop(audit);

        let (journal, _) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut terminal = Vec::new();
        let mut observations = Vec::new();
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["event_type"] == "sensor.observation" {
                    observations.push(event.clone());
                }
                if matches!(
                    event["event_type"].as_str(),
                    Some("edge.response" | "request.completed")
                ) && cases
                    .iter()
                    .any(|(_, _, request_id, _, _)| event["request_id"] == *request_id)
                {
                    terminal.push(event);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(terminal.len(), 8);
        for (index, (_, _, _, reason, edge_sequence)) in cases.iter().enumerate() {
            let edge = &terminal[index * 2];
            let completed = &terminal[index * 2 + 1];
            assert_eq!(edge["event_type"], "edge.response");
            assert_eq!(edge["request_seq"], *edge_sequence);
            assert_eq!(edge["payload"]["reason_code"], reason.as_str());
            assert_eq!(completed["payload"]["origin_state"], "not_sent");
            assert_eq!(completed["payload"]["reason_code"], reason.as_str());
        }
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["request_seq"], 3);
        assert_eq!(
            observations[0]["payload"]["binding_id"],
            observation.binding_id
        );
        assert_eq!(observations[0]["payload"]["claim_status"], "client_claimed");
        assert_eq!(observations[0]["payload"]["authorization_effect"], "none");
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn records_crypto_denial_before_decision_without_forward_intent() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let mut decision = config.admit("POST", "/orders", UnixSeconds::new(1));
        decision.outcome = GatewayOutcome::Denied;
        decision.reason_code = ReasonCode::RequestCryptoAuthenticationFailed;
        let crypto = RequestCryptoAudit::failed(
            config.request_crypto_rule("POST", "/orders").unwrap(),
            decision.reason_code,
            7,
        );
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000009";
        let admission = audit
            .commit_admission(AdmissionFacts {
                request_id,
                trace_id: "99999999999999999999999999999999",
                method: "POST",
                decision: &decision,
                duration_us: 10,
                request_crypto: Some(&crypto),
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        assert!(admission.forward_intent_event_id.is_none());
        drop(audit);

        let (journal, _) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut crypto_stage = None;
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["request_id"] == request_id && event["payload"]["stage"] == "crypto_decode"
                {
                    crypto_stage = Some(event);
                }
                Ok(())
            })
            .unwrap();
        let crypto_stage = crypto_stage.unwrap();
        assert_eq!(crypto_stage["request_seq"], 3);
        assert_eq!(
            crypto_stage["payload"]["reason_code"],
            ReasonCode::RequestCryptoAuthenticationFailed.as_str()
        );
        assert_eq!(
            crypto_stage["payload"]["coverage"]["origin_entity_rebuilt"],
            false
        );
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn records_opaque_observe_coverage_before_forward_intent() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("POST", "/orders-observe", UnixSeconds::new(1));
        let policy = config
            .request_crypto_policy("POST", "/orders-observe")
            .unwrap();
        let RequestCryptoPolicy::Observe(rule) = policy else {
            panic!("expected observe policy");
        };
        let crypto = RequestCryptoAudit::observed(rule);
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000019";
        let admission = audit
            .commit_admission(AdmissionFacts {
                request_id,
                trace_id: "19191919191919191919191919191919",
                method: "POST",
                decision: &decision,
                duration_us: 10,
                request_crypto: Some(&crypto),
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        assert!(admission.forward_intent_event_id.is_some());
        drop(audit);

        let (journal, _) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut observed = None;
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["request_id"] == request_id && event["payload"]["stage"] == "crypto_decode"
                {
                    observed = Some(event);
                }
                Ok(())
            })
            .unwrap();
        let observed = observed.unwrap();
        assert_eq!(observed["payload"]["facts"]["coverage_mode"], "OBSERVE");
        assert_eq!(
            observed["payload"]["facts"]["algorithm"],
            serde_json::Value::Null
        );
        assert_eq!(
            observed["payload"]["reason_code"],
            ReasonCode::RequestCryptoObservedOpaque.as_str()
        );
        assert_eq!(
            observed["payload"]["coverage"]["request_crypto_checked"],
            false
        );
        assert_eq!(
            observed["payload"]["coverage"]["origin_entity_rebuilt"],
            false
        );
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compatibility_audit_keeps_the_server_approval_and_page_evidence() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let policy = config
            .request_crypto_policy("POST", "/orders-legacy")
            .unwrap();
        let RequestCryptoPolicy::Compatibility(rule) = policy else {
            panic!("expected compatibility policy");
        };
        let evidence = PageEvidenceId::parse("page_018f2a3b-4c5d-7000-8000-000000000020").unwrap();
        let audit = RequestCryptoAudit::compatible(rule, &evidence, 7);
        assert_eq!(audit.coverage_mode, "COMPATIBILITY");
        assert_eq!(audit.approval_ref.as_deref(), Some("approval-42"));
        assert_eq!(
            audit.source_evidence_ref.as_deref(),
            Some(evidence.as_str())
        );
        assert_eq!(
            audit.reason_code,
            ReasonCode::RequestCryptoCompatibilityOpaque
        );
    }

    #[tokio::test]
    async fn distinguishes_complete_response_delivery_failure_from_truncation() {
        for (complete, event_type, origin_state, origin_reason, final_reason) in [
            (
                true,
                "origin.response",
                "response_received",
                "ORIGIN_RESPONSE_RECEIVED",
                "REQUEST_INCOMPLETE",
            ),
            (
                false,
                "origin.unknown",
                "unknown",
                "ORIGIN_OUTCOME_UNKNOWN",
                "ORIGIN_OUTCOME_UNKNOWN",
            ),
        ] {
            let directory = directory();
            let config = config(&directory, 1024 * 1024);
            let request_id = "req_018f2a3b-4c5d-7000-8000-000000000038";
            let trace_id = "38383838383838383838383838383838";
            let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
            let decision = config.admit("GET", "/health", UnixSeconds::new(1));
            let admission = audit
                .commit_admission(AdmissionFacts {
                    request_id,
                    trace_id,
                    method: "GET",
                    decision: &decision,
                    duration_us: 10,
                    request_crypto: None,
                    sensor_observations: &[],
                    sensor_bootstrap: None,
                    forward_origin: true,
                })
                .await
                .unwrap();
            audit
                .finalize(FinalFacts {
                    request_id,
                    trace_id,
                    method: "GET",
                    decision: &decision,
                    admission: &admission,
                    status: 502,
                    duration_us: 20,
                    proxy_error: true,
                    response_failure: None,
                    origin_status: Some(201),
                    origin_response_complete: complete,
                    response_crypto: None,
                    sensor_html: None,
                    page_actions: None,
                    response_source: ResponseSource::Origin,
                })
                .await
                .unwrap();
            drop(audit);
            let (journal, _) = LocalJournal::open(
                &directory,
                "journal-key-r1",
                JournalKey::from_hex(KEY).unwrap(),
                config.audit_limits(),
            )
            .unwrap();
            let mut terminal = Vec::new();
            journal
                .visit_closed_records(100, |record| {
                    let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                        .map_err(|_| JournalError::InvalidEvent)?;
                    if event["request_id"] == request_id
                        && matches!(
                            event["event_type"].as_str(),
                            Some("origin.response" | "origin.unknown" | "request.aborted")
                        )
                    {
                        terminal.push(event);
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(terminal.len(), 2);
            assert_eq!(terminal[0]["event_type"], event_type);
            assert_eq!(terminal[0]["payload"]["origin_state"], origin_state);
            assert_eq!(terminal[0]["payload"]["reason_code"], origin_reason);
            assert_eq!(
                terminal[0]["payload"]["status"],
                if complete {
                    serde_json::json!(201)
                } else {
                    serde_json::Value::Null
                }
            );
            assert_eq!(terminal[1]["event_type"], "request.aborted");
            assert_eq!(terminal[1]["payload"]["reason_code"], final_reason);
            assert_eq!(terminal[1]["payload"]["origin_state"], origin_state);
            assert_eq!(terminal[1]["payload"]["status"], 502);
            drop(journal);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[tokio::test]
    async fn records_response_validation_failure_as_received_and_aborted() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000008";
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("GET", "/health", UnixSeconds::new(1));
        let admission = audit
            .commit_admission(AdmissionFacts {
                request_id,
                trace_id: "88888888888888888888888888888888",
                method: "GET",
                decision: &decision,
                duration_us: 10,
                request_crypto: None,
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        let response_crypto = ResponseCryptoAudit::failed(
            config.response_crypto_rule("GET", "/health").unwrap(),
            ReasonCode::ResponseValidationFailed,
            5,
        );
        audit
            .finalize(FinalFacts {
                request_id,
                trace_id: "88888888888888888888888888888888",
                method: "GET",
                decision: &decision,
                admission: &admission,
                status: 200,
                duration_us: 20,
                proxy_error: true,
                response_failure: Some(ReasonCode::ResponseValidationFailed),
                origin_status: Some(200),
                origin_response_complete: false,
                response_crypto: Some(&response_crypto),
                sensor_html: None,
                page_actions: None,
                response_source: ResponseSource::Origin,
            })
            .await
            .unwrap();
        drop(audit);

        let (journal, _) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut terminal = Vec::new();
        let mut crypto_stage = None;
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["request_id"] == request_id
                    && matches!(
                        event["event_type"].as_str(),
                        Some("origin.response" | "request.aborted")
                    )
                {
                    terminal.push(event);
                } else if event["request_id"] == request_id
                    && event["payload"]["stage"] == "crypto_encode"
                {
                    crypto_stage = Some(event);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(terminal.len(), 2);
        assert_eq!(
            crypto_stage.unwrap()["payload"]["reason_code"],
            ReasonCode::ResponseValidationFailed.as_str()
        );
        assert_eq!(terminal[0]["payload"]["origin_state"], "response_received");
        assert_eq!(terminal[0]["payload"]["status"], 200);
        assert_eq!(
            terminal[1]["payload"]["reason_code"],
            ReasonCode::ResponseValidationFailed.as_str()
        );
        drop(journal);
        let restarted = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        assert!(restarted.is_ready());
        drop(restarted);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn reconciles_crashed_forward_once_before_reopening_traffic() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000004";
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("GET", "/health", UnixSeconds::new(1));
        audit
            .commit_admission(AdmissionFacts {
                request_id,
                trace_id: "44444444444444444444444444444444",
                method: "GET",
                decision: &decision,
                duration_us: 10,
                request_crypto: None,
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        drop(audit);

        let recovered = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        drop(recovered);
        let reopened = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        drop(reopened);

        let (journal, report) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        assert_eq!(report.recovered_records, 6);
        let mut terminal = Vec::new();
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["request_id"] == request_id
                    && matches!(
                        event["event_type"].as_str(),
                        Some("origin.unknown" | "request.aborted")
                    )
                {
                    terminal.push(event);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(terminal.len(), 2);
        assert_eq!(terminal[0]["event_type"], "origin.unknown");
        assert_eq!(terminal[0]["payload"]["origin_state"], "unknown");
        assert_eq!(terminal[1]["event_type"], "request.aborted");
        assert_eq!(terminal[1]["payload"]["status"], serde_json::Value::Null);
        assert_eq!(
            terminal[1]["payload"]["reason_code"],
            ReasonCode::OriginOutcomeUnknown.as_str()
        );
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn reconciles_denied_request_without_inventing_a_status() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000006";
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("GET", "/unknown", UnixSeconds::new(1));
        audit
            .commit_admission(AdmissionFacts {
                request_id,
                trace_id: "66666666666666666666666666666666",
                method: "GET",
                decision: &decision,
                duration_us: 10,
                request_crypto: None,
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap();
        drop(audit);

        drop(DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap());
        drop(DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap());

        let (journal, report) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        assert_eq!(report.recovered_records, 4);
        let mut terminal = Vec::new();
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["request_id"] == request_id && event["event_type"] == "request.aborted" {
                    terminal.push(event);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["payload"]["decision"], "DENY");
        assert_eq!(terminal[0]["payload"]["status"], serde_json::Value::Null);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reconciles_an_accepted_crash_prefix_once() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000007";
        append_accepted_prefix(
            &config,
            &directory,
            "tenant_test",
            request_id,
            "77777777777777777777777777777777",
        );

        drop(DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap());
        drop(DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap());

        let (journal, report) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        assert_eq!(report.recovered_records, 2);
        let mut terminal = Vec::new();
        journal
            .visit_closed_records(100, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["request_id"] == request_id && event["event_type"] == "request.aborted" {
                    terminal.push(event);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["payload"]["decision"], "UNKNOWN");
        assert_eq!(
            terminal[0]["payload"]["reason_code"],
            ReasonCode::RequestIncomplete.as_str()
        );
        assert_eq!(terminal[0]["payload"]["status"], serde_json::Value::Null);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_authenticated_history_from_another_scope() {
        let directory = directory();
        let config = config(&directory, 1024 * 1024);
        append_accepted_prefix(
            &config,
            &directory,
            "tenant_other",
            "req_018f2a3b-4c5d-7000-8000-000000000005",
            "55555555555555555555555555555555",
        );

        assert!(matches!(
            DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()),
            Err(DurableAuditError::Journal(JournalError::InvalidEvent))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn quota_failure_closes_the_admission_barrier() {
        let directory = directory();
        let config = config(&directory, 512);
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        let decision = config.admit("GET", "/health", UnixSeconds::new(1));
        let error = audit
            .commit_admission(AdmissionFacts {
                request_id: "req_018f2a3b-4c5d-7000-8000-000000000002",
                trace_id: "22222222222222222222222222222222",
                method: "GET",
                decision: &decision,
                duration_us: 10,
                request_crypto: None,
                sensor_observations: &[],
                sensor_bootstrap: None,
                forward_origin: true,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DurableAuditError::Journal(JournalError::Full)
        ));
        assert!(!audit.is_ready());
        drop(audit);
        fs::remove_dir_all(directory).unwrap();
    }

    fn health_facts<'a>(decision: &'a GatewayDecision, request_id: &'a str) -> AdmissionFacts<'a> {
        AdmissionFacts {
            request_id,
            trace_id: "22222222222222222222222222222222",
            method: "GET",
            decision,
            duration_us: 10,
            request_crypto: None,
            sensor_observations: &[],
            sensor_bootstrap: None,
            forward_origin: true,
        }
    }

    // Fills the journal until the barrier closes and returns how many
    // admissions were committed first.
    async fn fill_until_closed(audit: &DurableAudit, config: &GatewayConfig) -> usize {
        let decision = config.admit("GET", "/health", UnixSeconds::new(1));
        for committed in 0..10_000_usize {
            let request_id = format!("req_{}", Uuid::now_v7());
            if audit
                .commit_admission(health_facts(&decision, &request_id))
                .await
                .is_err()
            {
                return committed;
            }
        }
        panic!("the journal never filled");
    }

    fn remove_closed_segments(directory: &std::path::Path) -> usize {
        let mut removed = 0;
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let closed = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("segment-") && name.ends_with(".closed.xja"));
            if closed {
                // Closed segments are read-only; the publisher/retention role
                // that frees them owns the directory.
                let mut permissions = fs::metadata(&path).unwrap().permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false);
                fs::set_permissions(&path, permissions).unwrap();
                fs::remove_file(path).unwrap();
                removed += 1;
            }
        }
        removed
    }

    #[tokio::test]
    async fn a_closed_barrier_reopens_once_the_journal_has_room_and_records_it() {
        let directory = directory();
        let config = config_segmented(&directory, 48 * 1024, 2 * 1024);
        let audit = DurableAudit::open_recoverable(&config, KEY).unwrap();
        let committed = fill_until_closed(&audit, &config).await;
        assert!(committed > 0);
        assert!(!audit.is_ready(), "a durability failure closes the barrier");

        // Still full: probing must neither reopen nor create a segment.
        let segments_before = fs::read_dir(&directory).unwrap().count();
        assert!(audit.try_reopen().await.is_err());
        assert!(!audit.is_ready());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), segments_before);
        // Fail closed in between: admission is refused, not silently dropped.
        let decision = config.admit("GET", "/health", UnixSeconds::new(1));
        assert!(matches!(
            audit
                .commit_admission(health_facts(
                    &decision,
                    "req_018f2a3b-4c5d-7000-8000-000000000010"
                ))
                .await,
            Err(DurableAuditError::Unavailable)
        ));

        // The publisher or retention frees closed segments; the next probe
        // succeeds and admission resumes.
        assert!(remove_closed_segments(&directory) > 0);
        audit.try_reopen().await.unwrap();
        assert!(audit.is_ready());
        audit
            .commit_admission(health_facts(
                &decision,
                "req_018f2a3b-4c5d-7000-8000-000000000011",
            ))
            .await
            .expect("admission works after the barrier reopened");
        // Probing an open barrier is a no-op.
        audit.try_reopen().await.unwrap();

        // The reopen is part of the audit trail.
        drop(audit);
        let (journal, _) = LocalJournal::open(
            &directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut reopened = Vec::new();
        journal
            .visit_closed_records(10_000, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["event_type"] == "audit.recovered" {
                    reopened.push(event);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(reopened.len(), 1, "{reopened:?}");
        assert_eq!(
            reopened[0]["payload"]["reason_code"],
            ReasonCode::AuditBarrierReopened.as_str()
        );
        assert_eq!(reopened[0]["payload"]["truncated_bytes"], 0);
        drop(journal);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_writer_without_a_recoverable_key_stays_closed() {
        let directory = directory();
        let config = config_segmented(&directory, 48 * 1024, 2 * 1024);
        let audit = DurableAudit::open(&config, JournalKey::from_hex(KEY).unwrap()).unwrap();
        fill_until_closed(&audit, &config).await;
        assert!(remove_closed_segments(&directory) > 0);
        assert!(matches!(
            audit.try_reopen().await,
            Err(DurableAuditError::Unavailable)
        ));
        assert!(!audit.is_ready());
        drop(audit);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_backoff_doubles_up_to_its_bound() {
        let backoff = RecoveryBackoff {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(700),
        };
        let mut delay = backoff.initial;
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(delay.as_millis());
            delay = backoff.next(delay);
        }
        assert_eq!(seen, [100, 200, 400, 700, 700, 700]);
        let production = RecoveryBackoff::PRODUCTION;
        assert_eq!(production.initial, Duration::from_secs(1));
        assert_eq!(production.max, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn the_supervisor_reopens_a_failed_barrier_without_a_restart() {
        let directory = directory();
        let config = config_segmented(&directory, 48 * 1024, 2 * 1024);
        let audit = DurableAudit::open_recoverable(&config, KEY).unwrap();
        let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
        let supervisor = tokio::spawn(supervise_recovery(
            audit.clone(),
            RecoveryBackoff {
                initial: Duration::from_millis(10),
                max: Duration::from_millis(40),
            },
            shutdown,
        ));
        fill_until_closed(&audit, &config).await;
        // While nothing frees space the supervisor keeps probing and the
        // barrier stays closed.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!audit.is_ready());
        assert!(remove_closed_segments(&directory) > 0);
        let mut reopened = false;
        for _ in 0..200 {
            if audit.is_ready() {
                reopened = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(reopened, "the supervisor must reopen the barrier");
        let decision = config.admit("GET", "/health", UnixSeconds::new(1));
        audit
            .commit_admission(health_facts(
                &decision,
                "req_018f2a3b-4c5d-7000-8000-000000000012",
            ))
            .await
            .unwrap();
        shutdown_tx.send(true).unwrap();
        supervisor.await.unwrap();
        drop(audit);
        fs::remove_dir_all(directory).unwrap();
    }

    fn journal_events(
        directory: &std::path::Path,
        config: &GatewayConfig,
        event_type: &str,
    ) -> Vec<serde_json::Value> {
        let (journal, _) = LocalJournal::open(
            directory,
            "journal-key-r1",
            JournalKey::from_hex(KEY).unwrap(),
            config.audit_limits(),
        )
        .unwrap();
        let mut found = Vec::new();
        journal
            .visit_closed_records(100_000, |record| {
                let event: serde_json::Value = serde_json::from_slice(record.plaintext())
                    .map_err(|_| JournalError::InvalidEvent)?;
                if event["event_type"] == event_type {
                    found.push(event);
                }
                Ok(())
            })
            .unwrap();
        found
    }

    // The exact payload the worker's publisher accepts; the worker has a test
    // for the same literal, so the two sides cannot drift apart silently.
    #[tokio::test]
    async fn unrouted_denials_are_one_bounded_event_per_port_and_survive_a_closed_barrier() {
        use crate::unrouted::{UnroutedDenials, flush_once};
        let directory = directory();
        let config = config_segmented(&directory, 64 * 1024, 4 * 1024);
        let audit = DurableAudit::open_recoverable(&config, KEY).unwrap();
        let denials = UnroutedDenials::default();
        for _ in 0..5_000 {
            denials.record(6188, Some("Unknown.Example"), 1_700_000_000);
        }
        denials.record(6189, None, 1_700_000_005);

        // The journal fills and the barrier closes before the first flush.
        // Nothing counted is lost while it is closed: a failed flush puts the
        // counts back and later refusals merge into them.
        fill_until_closed(&audit, &config).await;
        flush_once(&audit, &denials).await;
        denials.record(6188, None, 1_700_000_100);
        let waiting = denials.take();
        assert_eq!(waiting.len(), 2, "{waiting:?}");
        denials.restore(waiting);
        assert!(remove_closed_segments(&directory) > 0);
        audit.try_reopen().await.unwrap();

        // One flush writes one event per port, however many requests were refused.
        flush_once(&audit, &denials).await;
        assert!(
            denials.take().is_empty(),
            "a successful flush drains the counts"
        );
        drop(audit);

        let mut events = journal_events(&directory, &config, "edge.unrouted_denied");
        events.sort_by_key(|event| event["payload"]["listener_port"].as_u64());
        assert_eq!(events.len(), 2, "{events:#?}");
        assert_eq!(
            events[0]["payload"],
            serde_json::json!({
                "listener_port": 6188,
                "denied_count": 5_001,
                "first_seen_unix": 1_700_000_000_u64,
                "last_seen_unix": 1_700_000_100_u64,
                "sample_host": "unknown.example",
                "reason_code": "HOST_NOT_ROUTED"
            })
        );
        assert_eq!(
            events[1]["payload"],
            serde_json::json!({
                "listener_port": 6189,
                "denied_count": 1,
                "first_seen_unix": 1_700_000_005_u64,
                "last_seen_unix": 1_700_000_005_u64,
                "sample_host": null,
                "reason_code": "HOST_NOT_ROUTED"
            })
        );
        for event in &events {
            assert_eq!(event["request_id"], serde_json::Value::Null);
            assert_eq!(event["tenant_id"], "tenant_test");
            assert_eq!(event["policy_revision"], "policy-r1");
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
