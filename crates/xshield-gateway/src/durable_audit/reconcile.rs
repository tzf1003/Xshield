use super::DurableAuditError;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};
use xshield_audit::{AuthenticatedJournalRecord, JournalError, LocalJournal};
use xshield_core::{
    audit::ReasonCode,
    domain::{PolicyRevision, RequestId},
};
use xshield_gateway::GatewayConfig;

pub(super) struct IncompleteRequest {
    pub(super) request_id: String,
    pub(super) trace_id: String,
    pub(super) policy_revision: String,
    pub(super) last_request_sequence: u32,
    pub(super) decision: RecoveredDecision,
    pub(super) forward: Option<RecoveredForward>,
    pub(super) origin: Option<RecoveredOrigin>,
}

struct RecoveryState {
    request_id: String,
    trace_id: String,
    policy_revision: String,
    last_request_sequence: u32,
    request_sequences: BTreeSet<u32>,
    accepted_event_id: Option<String>,
    decision: Option<RecoveredDecision>,
    forward: Option<RecoveredForward>,
    origin: Option<RecoveredOrigin>,
    terminal: Option<RecoveredTerminal>,
}

pub(super) struct RecoveredDecision {
    pub(super) event_id: String,
    pub(super) outcome: String,
    pub(super) reason_code: String,
}

pub(super) struct RecoveredForward {
    pub(super) event_id: String,
    pub(super) method: String,
    pub(super) operation_id: Option<String>,
}

pub(super) struct RecoveredOrigin {
    pub(super) event_id: String,
    method: String,
    operation_id: Option<String>,
    pub(super) state: String,
    pub(super) status: Option<u16>,
}

struct RecoveredTerminal {
    event_type: String,
    decision: String,
    reason_code: String,
    status: Option<u16>,
    origin_state: String,
}

#[derive(Deserialize)]
struct HistoricalEvent {
    schema_version: u8,
    event_id: String,
    event_type: String,
    tenant_id: String,
    site_id: String,
    request_id: Option<String>,
    trace_id: String,
    span_id: String,
    producer_boot_id: String,
    producer_seq: u64,
    request_seq: u32,
    policy_revision: String,
    example_only: bool,
    payload: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalAccepted {
    method: String,
    operation_id: Option<String>,
    origin_state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalDecision {
    decision: String,
    reason_code: String,
    origin_state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalOrigin {
    method: String,
    operation_id: Option<String>,
    origin_state: String,
    reason_code: String,
    status: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalCompletion {
    decision: String,
    reason_code: String,
    status: Option<u16>,
    origin_state: String,
    duration_us: u64,
}

pub(super) fn incomplete_requests(
    journal: &LocalJournal,
    config: &GatewayConfig,
) -> Result<Vec<IncompleteRequest>, DurableAuditError> {
    let mut requests = BTreeMap::<String, RecoveryState>::new();
    journal.visit_closed_records(config.audit_reconcile_max_records(), |record| {
        apply_historical_event(record, config, &mut requests)
            .map_err(|_| JournalError::InvalidEvent)
    })?;
    requests
        .into_values()
        .map(|request| {
            validate_recovery_state(&request)?;
            if request.terminal.is_some() {
                return Ok(None);
            }
            let decision = request.decision.unwrap_or(RecoveredDecision {
                event_id: request
                    .accepted_event_id
                    .ok_or(DurableAuditError::InvalidHistoricalEvent)?,
                outcome: "UNKNOWN".to_owned(),
                reason_code: ReasonCode::RequestIncomplete.as_str().to_owned(),
            });
            Ok(Some(IncompleteRequest {
                request_id: request.request_id,
                trace_id: request.trace_id,
                policy_revision: request.policy_revision,
                last_request_sequence: request.last_request_sequence,
                decision,
                forward: request.forward,
                origin: request.origin,
            }))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|requests| requests.into_iter().flatten().collect())
}

fn apply_historical_event(
    record: &AuthenticatedJournalRecord,
    config: &GatewayConfig,
    requests: &mut BTreeMap<String, RecoveryState>,
) -> Result<(), DurableAuditError> {
    let event: HistoricalEvent = serde_json::from_slice(record.plaintext())?;
    if event.schema_version != 3
        || event.event_id != record.event_id().as_str()
        || event.producer_boot_id != record.producer_boot_id()
        || event.producer_seq != record.producer_sequence()
        || event.tenant_id != config.tenant_id().as_str()
        || event.site_id != config.site_id().as_str()
        || event.request_seq == 0
        || event.example_only
        || !valid_lower_hex(&event.trace_id, 32)
        || !valid_lower_hex(&event.span_id, 16)
        || PolicyRevision::parse(event.policy_revision.clone()).is_err()
    {
        return Err(DurableAuditError::InvalidHistoricalEvent);
    }
    let Some(request_id) = event.request_id.as_ref() else {
        return Ok(());
    };
    RequestId::parse(request_id.clone()).map_err(DurableAuditError::InvalidId)?;
    let request = requests
        .entry(request_id.clone())
        .or_insert_with(|| RecoveryState {
            request_id: request_id.clone(),
            trace_id: event.trace_id.clone(),
            policy_revision: event.policy_revision.clone(),
            last_request_sequence: 0,
            request_sequences: BTreeSet::new(),
            accepted_event_id: None,
            decision: None,
            forward: None,
            origin: None,
            terminal: None,
        });
    if request.trace_id != event.trace_id
        || request.policy_revision != event.policy_revision
        || !request.request_sequences.insert(event.request_seq)
    {
        return Err(DurableAuditError::InvalidHistoricalEvent);
    }
    request.last_request_sequence = request.last_request_sequence.max(event.request_seq);
    apply_request_event(request, event)
}

fn apply_request_event(
    request: &mut RecoveryState,
    event: HistoricalEvent,
) -> Result<(), DurableAuditError> {
    match event.event_type.as_str() {
        "request.accepted" => {
            let payload: HistoricalAccepted = serde_json::from_str(event.payload.get())?;
            if request.accepted_event_id.is_some()
                || event.request_seq != 1
                || payload.origin_state != "not_sent"
                || !valid_method(&payload.method)
                || invalid_operation(payload.operation_id.as_deref())
            {
                return Err(DurableAuditError::InvalidHistoricalEvent);
            }
            request.accepted_event_id = Some(event.event_id);
        }
        "decision.composed" => {
            let payload: HistoricalDecision = serde_json::from_str(event.payload.get())?;
            if request.decision.is_some()
                || !matches!(payload.decision.as_str(), "ALLOW" | "DENY")
                || payload.origin_state != "not_sent"
                || !valid_reason_code(&payload.reason_code)
            {
                return Err(DurableAuditError::InvalidHistoricalEvent);
            }
            request.decision = Some(RecoveredDecision {
                event_id: event.event_id,
                outcome: payload.decision,
                reason_code: payload.reason_code,
            });
        }
        "origin.forward_intent" => {
            let payload: HistoricalOrigin = serde_json::from_str(event.payload.get())?;
            if request.forward.is_some()
                || payload.origin_state != "not_sent"
                || payload.reason_code != ReasonCode::OriginForwardIntentRecorded.as_str()
                || payload.status.is_some()
                || !valid_method(&payload.method)
                || invalid_operation(payload.operation_id.as_deref())
            {
                return Err(DurableAuditError::InvalidHistoricalEvent);
            }
            request.forward = Some(RecoveredForward {
                event_id: event.event_id,
                method: payload.method,
                operation_id: payload.operation_id,
            });
        }
        "origin.response" | "origin.unknown" => {
            let payload: HistoricalOrigin = serde_json::from_str(event.payload.get())?;
            let valid_response = event.event_type == "origin.response"
                && payload.origin_state == "response_received"
                && payload.reason_code == ReasonCode::OriginResponseReceived.as_str()
                && payload
                    .status
                    .is_some_and(|status| (100..=599).contains(&status));
            let valid_unknown = event.event_type == "origin.unknown"
                && payload.origin_state == "unknown"
                && payload.reason_code == ReasonCode::OriginOutcomeUnknown.as_str()
                && payload.status.is_none();
            if request.origin.is_some()
                || !(valid_response || valid_unknown)
                || !valid_method(&payload.method)
                || invalid_operation(payload.operation_id.as_deref())
            {
                return Err(DurableAuditError::InvalidHistoricalEvent);
            }
            request.origin = Some(RecoveredOrigin {
                event_id: event.event_id,
                method: payload.method,
                operation_id: payload.operation_id,
                state: payload.origin_state,
                status: payload.status,
            });
        }
        "request.completed" | "request.aborted" => {
            let payload: HistoricalCompletion = serde_json::from_str(event.payload.get())?;
            if request.terminal.is_some()
                || !matches!(payload.decision.as_str(), "ALLOW" | "DENY" | "UNKNOWN")
                || !valid_reason_code(&payload.reason_code)
                || (event.event_type == "request.completed" && payload.status.is_none())
                || (payload.decision == "UNKNOWN" && event.event_type != "request.aborted")
            {
                return Err(DurableAuditError::InvalidHistoricalEvent);
            }
            let _ = payload.duration_us;
            request.terminal = Some(RecoveredTerminal {
                event_type: event.event_type,
                decision: payload.decision,
                reason_code: payload.reason_code,
                status: payload.status,
                origin_state: payload.origin_state,
            });
        }
        _ => {}
    }
    Ok(())
}

fn validate_recovery_state(request: &RecoveryState) -> Result<(), DurableAuditError> {
    if request.accepted_event_id.is_none()
        || request.forward.is_some()
            && request
                .decision
                .as_ref()
                .map(|decision| decision.outcome.as_str())
                != Some("ALLOW")
        || request.origin.is_some() && request.forward.is_none()
        || request.decision.is_none() && (request.forward.is_some() || request.origin.is_some())
    {
        return Err(DurableAuditError::InvalidHistoricalEvent);
    }
    if let Some(origin) = &request.origin {
        let forward = request
            .forward
            .as_ref()
            .ok_or(DurableAuditError::InvalidHistoricalEvent)?;
        if origin.method != forward.method || origin.operation_id != forward.operation_id {
            return Err(DurableAuditError::InvalidHistoricalEvent);
        }
    }
    let Some(terminal) = &request.terminal else {
        return Ok(());
    };
    let terminal_matches = match (&request.origin, request.decision.as_ref()) {
        (None, None) => {
            terminal.event_type == "request.aborted"
                && terminal.decision == "UNKNOWN"
                && terminal.origin_state == "not_sent"
                && terminal.reason_code == ReasonCode::RequestIncomplete.as_str()
                && terminal.status.is_none()
        }
        (None, Some(decision)) if decision.outcome == "DENY" => {
            terminal.origin_state == "not_sent"
                && terminal.reason_code == decision.reason_code
                && ((terminal.event_type == "request.completed" && terminal.status.is_some())
                    || (terminal.event_type == "request.aborted" && terminal.status.is_none()))
        }
        (None, Some(decision)) if decision.outcome == "ALLOW" => {
            terminal.event_type == "request.aborted"
                && terminal.origin_state == "not_sent"
                && terminal.reason_code == ReasonCode::RequestIncomplete.as_str()
                && terminal.status.is_none()
        }
        (Some(origin), Some(decision))
            if decision.outcome == "ALLOW" && origin.state == "response_received" =>
        {
            terminal.event_type == "request.completed"
                && terminal.origin_state == origin.state
                && terminal.reason_code == ReasonCode::OriginResponseReceived.as_str()
                && terminal.status == origin.status
        }
        (Some(origin), Some(decision))
            if decision.outcome == "ALLOW" && origin.state == "unknown" =>
        {
            terminal.event_type == "request.aborted"
                && terminal.origin_state == origin.state
                && terminal.reason_code == ReasonCode::OriginOutcomeUnknown.as_str()
        }
        _ => false,
    };
    if request
        .decision
        .as_ref()
        .is_some_and(|decision| terminal.decision != decision.outcome)
        || terminal
            .status
            .is_some_and(|status| !(100..=599).contains(&status))
        || !terminal_matches
    {
        return Err(DurableAuditError::InvalidHistoricalEvent);
    }
    Ok(())
}

fn valid_method(value: &str) -> bool {
    matches!(
        value,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

fn invalid_operation(value: Option<&str>) -> bool {
    value.is_some_and(|value| !valid_audit_name(value))
}

fn valid_audit_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
