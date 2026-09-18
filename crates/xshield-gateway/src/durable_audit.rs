use chrono::{SecondsFormat, Utc};
mod reconcile;

use reconcile::{IncompleteRequest, incomplete_requests};
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

use xshield_gateway::request_crypto::{RequestCryptoEvidence, RequestCryptoRule};
use xshield_gateway::response_crypto::{ResponseCryptoEvidence, ResponseCryptoRule};
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
    pub(crate) request_crypto: Option<&'a RequestCryptoAudit>,
}

#[derive(Clone, Debug)]
pub(crate) struct RequestCryptoAudit {
    algorithm: &'static str,
    adapter_revision: String,
    key_id: String,
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
            algorithm: evidence.algorithm(),
            adapter_revision: evidence.adapter_revision().to_owned(),
            key_id: evidence.key_id().to_owned(),
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
            algorithm: rule.algorithm(),
            adapter_revision: rule.adapter_revision().to_owned(),
            key_id: rule.key_id().to_owned(),
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
    pub(crate) response_crypto: Option<&'a ResponseCryptoAudit>,
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
        audit.record_incomplete(incomplete)?;
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
                        algorithm: crypto.algorithm,
                        adapter_revision: crypto.adapter_revision.clone(),
                        key_id: crypto.key_id.clone(),
                        message_id: crypto.message_id.clone(),
                        nonce_sha256: crypto.nonce_sha256.clone(),
                        issued_at: crypto.issued_at,
                        expires_at: crypto.expires_at,
                        envelope_sha256: crypto.envelope_sha256.clone(),
                        rebuilt_sha256: crypto.rebuilt_sha256.clone(),
                    },
                    coverage: CryptoStageCoverage {
                        request_crypto_checked: true,
                        origin_entity_rebuilt: crypto.rebuilt_sha256.is_some(),
                    },
                },
            ));
            last_stage_id = String::from(crypto_id.as_str());
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
        let forward_intent_id = if facts.decision.outcome == GatewayOutcome::Allowed {
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
                + u32::from(facts.decision.outcome == GatewayOutcome::Allowed),
        })
    }

    pub(crate) async fn finalize(&self, facts: FinalFacts<'_>) -> Result<(), DurableAuditError> {
        let origin = final_origin(&facts);
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
                origin.event_type,
                request_sequence,
                forward_cause,
                Payload::Origin {
                    method: facts.method.to_owned(),
                    operation_id: facts
                        .decision
                        .operation_id
                        .as_ref()
                        .map(|operation| operation.as_str().to_owned()),
                    origin_state: origin.state,
                    reason_code: origin.reason_code,
                    status: origin.status,
                },
            ));
            completion_causes.push(origin_id.as_str().to_owned());
            request_sequence = request_sequence
                .checked_add(1)
                .ok_or(DurableAuditError::SequenceExhausted)?;
        }
        if let Some(crypto) = facts.response_crypto {
            let (crypto_id, event) = response_crypto_event(
                crypto,
                facts
                    .decision
                    .operation_id
                    .as_ref()
                    .map(|operation| operation.as_str().to_owned()),
                request_sequence,
                completion_causes.clone(),
            )?;
            events.push(event);
            completion_causes.push(crypto_id.as_str().to_owned());
            request_sequence = request_sequence
                .checked_add(1)
                .ok_or(DurableAuditError::SequenceExhausted)?;
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
                origin_state: origin.state.to_owned(),
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
                    let event_type = if origin.state == "response_received" {
                        "request.completed"
                    } else {
                        "request.aborted"
                    };
                    let reason_code = if origin.state == "response_received" {
                        ReasonCode::OriginResponseReceived.as_str()
                    } else {
                        ReasonCode::OriginOutcomeUnknown.as_str()
                    };
                    (
                        event_type,
                        origin.event_id,
                        reason_code.to_owned(),
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
                algorithm: crypto.algorithm,
                adapter_revision: crypto.adapter_revision.clone(),
                key_id: crypto.key_id.clone(),
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
    facts.response_failure.map_or_else(
        || {
            if facts.decision.outcome == GatewayOutcome::Denied {
                facts.decision.reason_code.as_str()
            } else if facts.proxy_error {
                ReasonCode::OriginOutcomeUnknown.as_str()
            } else {
                ReasonCode::OriginResponseReceived.as_str()
            }
        },
        ReasonCode::as_str,
    )
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
    algorithm: &'static str,
    adapter_revision: String,
    key_id: String,
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
                "high_watermark_bytes": max_bytes / 2,
                "segment_max_bytes": max_bytes
            },
            "identity_store": {
                "max_connections": 2,
                "acquire_timeout_ms": 1000
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
                }
            ]
        });
        GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()).unwrap()
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
                response_crypto: None,
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
                response_crypto: None,
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
                response_crypto: Some(&response_crypto),
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
