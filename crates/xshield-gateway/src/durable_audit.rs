use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use tokio::task::JoinError;
use uuid::Uuid;
use xshield_audit::{
    JournalError, JournalKey, JournalReceipt, JournalRecord, LocalJournal, RecoveryReport,
};
use xshield_core::audit::ReasonCode;
use xshield_core::domain::{EventId, InvalidValue};

use xshield_gateway::{GatewayConfig, GatewayDecision, GatewayOutcome};

#[derive(Clone)]
pub(crate) struct DurableAudit {
    journal: Arc<Mutex<LocalJournal>>,
    ready: Arc<AtomicBool>,
    failure_code: Arc<AtomicU8>,
    tenant_id: String,
    site_id: String,
    policy_revision: String,
    producer_id: String,
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
}

impl DurableAudit {
    pub(crate) fn open(config: &GatewayConfig, key: JournalKey) -> Result<Self, DurableAuditError> {
        let (journal, recovery) = LocalJournal::open(
            config.audit_directory(),
            config.audit_key_id(),
            key,
            config.audit_limits(),
        )?;
        let audit = Self {
            journal: Arc::new(Mutex::new(journal)),
            ready: Arc::new(AtomicBool::new(true)),
            failure_code: Arc::new(AtomicU8::new(0)),
            tenant_id: config.tenant_id().as_str().to_owned(),
            site_id: config.site_id().as_str().to_owned(),
            policy_revision: config.policy_revision().as_str().to_owned(),
            producer_id: config.audit_producer_id().to_owned(),
        };
        if recovery.truncated_bytes > 0 {
            audit.record_recovery(recovery)?;
        }
        Ok(audit)
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) && self.failure_code.load(Ordering::Acquire) == 0
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
        };
        self.failure_code.store(code, Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

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
                    facts: StageFacts { operation_id },
                    coverage: StageCoverage {
                        admission_checked: true,
                    },
                },
            ),
            PendingEvent::new(
                decision_id.clone(),
                "decision.composed",
                3,
                vec![stage_id.as_str().to_owned()],
                Payload::Decision {
                    decision,
                    reason_code: facts.decision.reason_code.as_str(),
                    origin_state: "not_sent",
                },
            ),
        ];
        let forward_intent_id = if facts.decision.outcome == GatewayOutcome::Allowed {
            let event_id = new_event_id()?;
            events.push(PendingEvent::new(
                event_id.clone(),
                "origin.forward_intent",
                4,
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
            next_request_sequence: if facts.decision.outcome == GatewayOutcome::Allowed {
                5
            } else {
                4
            },
        })
    }

    pub(crate) async fn finalize(&self, facts: FinalFacts<'_>) -> Result<(), DurableAuditError> {
        let origin_state = match (facts.decision.outcome, facts.proxy_error) {
            (GatewayOutcome::Denied, _) => "not_sent",
            (GatewayOutcome::Allowed, false) => "response_received",
            (GatewayOutcome::Allowed, true) => "unknown",
        };
        let mut events = Vec::new();
        let mut request_sequence = facts.admission.next_request_sequence;
        let mut completion_causes = vec![facts.admission.decision_event_id.clone()];
        if facts.decision.outcome == GatewayOutcome::Allowed {
            let origin_id = new_event_id()?;
            let forward_cause = facts
                .admission
                .forward_intent_event_id
                .iter()
                .cloned()
                .collect();
            events.push(PendingEvent::new(
                origin_id.clone(),
                if facts.proxy_error {
                    "origin.unknown"
                } else {
                    "origin.response"
                },
                request_sequence,
                forward_cause,
                Payload::Origin {
                    method: facts.method.to_owned(),
                    operation_id: facts
                        .decision
                        .operation_id
                        .as_ref()
                        .map(|operation| operation.as_str().to_owned()),
                    origin_state,
                    reason_code: if facts.proxy_error {
                        ReasonCode::OriginOutcomeUnknown.as_str()
                    } else {
                        ReasonCode::OriginResponseReceived.as_str()
                    },
                    status: (!facts.proxy_error).then_some(facts.status),
                },
            ));
            completion_causes.push(origin_id.as_str().to_owned());
            request_sequence = request_sequence
                .checked_add(1)
                .ok_or(DurableAuditError::SequenceExhausted)?;
        }
        let completion_id = new_event_id()?;
        events.push(PendingEvent::new(
            completion_id,
            if facts.proxy_error {
                "request.aborted"
            } else {
                "request.completed"
            },
            request_sequence,
            completion_causes,
            Payload::RequestCompleted {
                decision: match facts.decision.outcome {
                    GatewayOutcome::Allowed => "ALLOW",
                    GatewayOutcome::Denied => "DENY",
                },
                reason_code: match (facts.decision.outcome, facts.proxy_error) {
                    (GatewayOutcome::Allowed, true) => ReasonCode::OriginOutcomeUnknown.as_str(),
                    (GatewayOutcome::Allowed, false) => ReasonCode::OriginResponseReceived.as_str(),
                    (GatewayOutcome::Denied, _) => facts.decision.reason_code.as_str(),
                },
                status: facts.status,
                origin_state,
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

fn append_locked(
    journal: &Arc<Mutex<LocalJournal>>,
    tenant_id: &str,
    site_id: &str,
    policy_revision: &str,
    producer_id: &str,
    context: &BatchContext,
    events: &[PendingEvent],
) -> Result<Vec<JournalReceipt>, DurableAuditError> {
    let mut journal = journal
        .lock()
        .map_err(|_| DurableAuditError::LockPoisoned)?;
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
        evidence_refs: &[],
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
            payload,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Payload {
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
    RequestCompleted {
        decision: &'static str,
        reason_code: &'static str,
        status: u16,
        origin_state: &'static str,
        duration_us: u64,
    },
    Recovery {
        recovered_records: u64,
        truncated_bytes: u64,
        reason_code: &'static str,
    },
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
    evidence_refs: &'a [&'a str],
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
            | Self::Unavailable => None,
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

    const KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!("xshield-gateway-audit-{}", Uuid::now_v7()))
    }

    fn config(directory: &std::path::Path, max_bytes: u64) -> GatewayConfig {
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
                "high_watermark_bytes": max_bytes / 2
            },
            "operations": [{
                "operation_id": "health.read",
                "method": "GET",
                "path": "/health",
                "admission": "PUBLIC",
                "source_action": null,
                "resource_type": null,
                "view_profile": null
            }]
        });
        GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()).unwrap()
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
}
