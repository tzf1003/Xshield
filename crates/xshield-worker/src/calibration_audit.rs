//! Strict publication of calibration plaintext-release audit facts.
//!
//! The calibration reader appends this event to its dedicated encrypted journal
//! after vault authentication but before it gives plaintext to the evaluator.
//! This is intentionally not an outbox event: local journal durability is the
//! release barrier, while indexing may occur later. The payload is deliberately
//! unable to name the selected artifact, semantic role, sample slot, lease, or
//! opaque lease handle.

use super::{PayloadSummary, PublishError, WireEvent, valid_prefixed_v7, valid_uuid_v7};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::json;
use std::fmt;
use uuid::{Uuid, Version};
use xshield_audit::{JournalError, JournalReceipt, JournalRecord, LocalJournal};
use xshield_core::domain::{CalibrationReadCapabilityId, EventId, SiteId, TenantId};

#[cfg(test)]
mod tests;

const EVENT_TYPE: &str = "calibration.evidence_read";
const PRODUCER_ID: &str = "calibration-evidence-reader";
const POLICY_REVISION: &str = "calibration-v1";
const MAX_RELEASED_BYTES: u64 = 512 * 1024 * 1024;

/// The final outcome recorded immediately before an evaluator can receive
/// calibration plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationEvidenceReadOutcome {
    /// Vault-authenticated plaintext is about to cross the reader boundary.
    Released {
        /// Exact bounded plaintext bytes about to be released.
        bytes_released: u64,
    },
    /// Capability, lease, member, or current catalog checks denied the read.
    NotAuthorized,
    /// The authoritative authorization dependency could not be consulted.
    AuthorizationUnavailable,
    /// A bounded reader or journal admission reservation was unavailable.
    CapacityUnavailable,
    /// Manifest, ciphertext digest, or AEAD validation failed.
    IntegrityFailed,
    /// The encrypted vault object could not be read safely.
    VaultUnavailable,
    /// Cancellation was observed before plaintext crossed the reader boundary.
    Cancelled,
}

impl CalibrationEvidenceReadOutcome {
    fn wire(self) -> Result<(&'static str, &'static str, Option<u64>), CalibrationAuditBuildError> {
        match self {
            Self::Released { bytes_released } => {
                if !(1..=MAX_RELEASED_BYTES).contains(&bytes_released) {
                    return Err(CalibrationAuditBuildError::ReleasedBytesOutOfRange);
                }
                Ok((
                    "PASS",
                    "CALIBRATION_EVIDENCE_READ_RELEASED",
                    Some(bytes_released),
                ))
            }
            Self::NotAuthorized => Ok(("DENY", "CALIBRATION_EVIDENCE_READ_NOT_AUTHORIZED", None)),
            Self::AuthorizationUnavailable => Ok((
                "ERROR",
                "CALIBRATION_EVIDENCE_READ_AUTHORIZATION_UNAVAILABLE",
                None,
            )),
            Self::CapacityUnavailable => Ok((
                "ERROR",
                "CALIBRATION_EVIDENCE_READ_CAPACITY_UNAVAILABLE",
                None,
            )),
            Self::IntegrityFailed => {
                Ok(("ERROR", "CALIBRATION_EVIDENCE_READ_INTEGRITY_FAILED", None))
            }
            Self::VaultUnavailable => {
                Ok(("ERROR", "CALIBRATION_EVIDENCE_READ_VAULT_UNAVAILABLE", None))
            }
            Self::Cancelled => Ok(("ERROR", "CALIBRATION_EVIDENCE_READ_CANCELLED", None)),
        }
    }
}

/// Failure while preparing a closed calibration-read journal event.
#[derive(Debug)]
pub enum CalibrationAuditBuildError {
    /// The journal has no next producer sequence to bind into the event.
    SequenceExhausted,
    /// A released plaintext length is zero or exceeds the batch hard limit.
    ReleasedBytesOutOfRange,
    /// The local journal did not supply a canonical `UUIDv7` producer boot ID.
    InvalidProducerBootId,
    /// The event cannot be serialized into its canonical JSON envelope.
    Serialization(serde_json::Error),
}

impl fmt::Display for CalibrationAuditBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SequenceExhausted => formatter.write_str("calibration audit sequence exhausted"),
            Self::ReleasedBytesOutOfRange => formatter
                .write_str("calibration released byte count is outside the configured bound"),
            Self::InvalidProducerBootId => {
                formatter.write_str("calibration audit journal producer boot identifier is invalid")
            }
            Self::Serialization(_) => {
                formatter.write_str("calibration audit event serialization failed")
            }
        }
    }
}

impl std::error::Error for CalibrationAuditBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

/// One immutable calibration plaintext-release event frozen for journal append.
///
/// Build this event after a terminal authorization or vault result is known and,
/// for [`CalibrationEvidenceReadOutcome::Released`], after decryption but
/// before the bytes leave the reader. Call [`Self::append`] successfully before
/// returning plaintext. A failed append produces no durable terminal event and
/// must block the release rather than being represented as a successful audit.
pub struct CalibrationEvidenceReadAuditEvent {
    event_id: EventId,
    producer_sequence: u64,
    bytes: Vec<u8>,
}

impl CalibrationEvidenceReadAuditEvent {
    /// Freezes the event identity and canonical bytes using the active journal's
    /// next authenticated sequence.
    ///
    /// The returned value is reusable only for an exact journal retry; a later
    /// physical plaintext release must call this method again to obtain a new
    /// event ID. Preparation has no audit or vault side effect.
    ///
    /// # Errors
    /// Returns [`CalibrationAuditBuildError`] when the journal sequence or boot
    /// identity is invalid, the outcome bytes are out of bounds, or JSON cannot
    /// be serialized.
    pub fn prepare(
        journal: &LocalJournal,
        tenant_id: &TenantId,
        site_id: &SiteId,
        capability_id: &CalibrationReadCapabilityId,
        outcome: CalibrationEvidenceReadOutcome,
    ) -> Result<Self, CalibrationAuditBuildError> {
        let producer_sequence = journal
            .next_sequence()
            .ok_or(CalibrationAuditBuildError::SequenceExhausted)?;
        let producer_boot_id = journal.producer_boot_id();
        let boot = Uuid::parse_str(&producer_boot_id)
            .map_err(|_| CalibrationAuditBuildError::InvalidProducerBootId)?;
        if boot.get_version() != Some(Version::SortRand)
            || producer_boot_id != boot.hyphenated().to_string()
        {
            return Err(CalibrationAuditBuildError::InvalidProducerBootId);
        }
        let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| {
            CalibrationAuditBuildError::Serialization(serde_json::Error::io(std::io::Error::other(
                "generated calibration audit event id is invalid",
            )))
        })?;
        let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let trace_id = capability_id
            .as_str()
            .strip_prefix("calcap_")
            .ok_or(CalibrationAuditBuildError::Serialization(
                serde_json::Error::io(std::io::Error::other(
                    "calibration capability id is invalid",
                )),
            ))?
            .replace('-', "");
        let span_id = event_id
            .as_str()
            .strip_prefix("ev_")
            .ok_or(CalibrationAuditBuildError::Serialization(
                serde_json::Error::io(std::io::Error::other(
                    "calibration audit event id is invalid",
                )),
            ))?
            .replace('-', "");
        let (outcome, reason_code, bytes_released) = outcome.wire()?;
        let payload = match bytes_released {
            Some(bytes_released) => json!({
                "stage": "calibration_evidence_read", "outcome": outcome,
                "reason_code": reason_code, "capability_id": capability_id.as_str(),
                "bytes_released": bytes_released
            }),
            None => json!({
                "stage": "calibration_evidence_read", "outcome": outcome,
                "reason_code": reason_code, "capability_id": capability_id.as_str()
            }),
        };
        let envelope = json!({
            "schema_version": 3, "event_id": event_id.as_str(), "event_type": EVENT_TYPE,
            "tenant_id": tenant_id.as_str(), "site_id": site_id.as_str(), "request_id": null,
            "trace_id": trace_id, "span_id": &span_id[..16],
            "producer_id": PRODUCER_ID, "producer_boot_id": producer_boot_id,
            "producer_seq": producer_sequence, "request_seq": 1,
            "occurred_at": occurred_at, "observed_at": occurred_at,
            "policy_revision": POLICY_REVISION, "example_only": false,
            "evidence_refs": [], "cause_event_ids": [], "payload": payload,
            "sensitivity": "RESTRICTED",
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
        });
        Ok(Self {
            event_id,
            producer_sequence,
            bytes: serde_json::to_vec(&envelope)
                .map_err(CalibrationAuditBuildError::Serialization)?,
        })
    }

    /// Returns the immutable event identity retained for an exact append retry.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Appends the frozen event and synchronizes it before a reader releases
    /// plaintext. The receipt must bind this event and the frozen next sequence.
    ///
    /// # Errors
    /// Returns [`JournalError`] when the encrypted journal cannot durably
    /// acknowledge this event. Callers must return their own audit-unavailable
    /// error and withhold plaintext on every error path.
    pub fn append(&self, journal: &mut LocalJournal) -> Result<JournalReceipt, JournalError> {
        // A prepared envelope embeds the authenticated producer sequence. Do
        // not append it after another writer advanced the journal: the journal
        // accepts opaque bytes, so discovering the mismatch from its receipt
        // would otherwise leave an internally inconsistent durable record.
        let expected_sequence = journal.next_sequence().ok_or(JournalError::Full)?;
        if expected_sequence != self.producer_sequence {
            return Err(JournalError::InvalidEvent);
        }
        let receipts = journal.append_batch(&[JournalRecord {
            event_id: &self.event_id,
            plaintext: &self.bytes,
        }])?;
        let Some(receipt) = receipts.into_iter().next() else {
            return Err(JournalError::Corrupt("calibration audit receipt"));
        };
        if receipt.event_id != self.event_id || receipt.producer_sequence != expected_sequence {
            return Err(JournalError::Corrupt("calibration audit receipt"));
        }
        Ok(receipt)
    }
}

/// Returns whether an event belongs to the dedicated calibration-read journal
/// contract instead of the generic request-stage payload contract.
pub(super) fn supports(event_type: &str) -> bool {
    event_type == EVENT_TYPE
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationEvidenceRead {
    stage: String,
    outcome: String,
    reason_code: String,
    capability_id: String,
    bytes_released: Option<u64>,
}

/// Validates one terminal calibration plaintext-release event.
///
/// The authenticated journal sequence and producer boot identity are validated
/// by the common journal reader before this parser runs. This parser binds the
/// released-byte fact to a capability trace without turning the analytical
/// index into a source-artifact or lease directory.
pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: CalibrationEvidenceRead = serde_json::from_str(event.payload.get())?;
    let capability_id = CalibrationReadCapabilityId::parse(value.capability_id.clone())
        .map_err(|_| PublishError::InvalidEvent)?;
    let capability_trace = capability_id
        .as_str()
        .strip_prefix("calcap_")
        .ok_or(PublishError::InvalidEvent)?
        .replace('-', "");
    let event_id =
        EventId::parse(event.event_id.clone()).map_err(|_| PublishError::InvalidEvent)?;
    let event_span = event_id
        .as_str()
        .strip_prefix("ev_")
        .ok_or(PublishError::InvalidEvent)?
        .replace('-', "");
    let valid_terminal = match (value.outcome.as_str(), value.reason_code.as_str()) {
        ("PASS", "CALIBRATION_EVIDENCE_READ_RELEASED") => value
            .bytes_released
            .is_some_and(|bytes| (1..=MAX_RELEASED_BYTES).contains(&bytes)),
        ("DENY", "CALIBRATION_EVIDENCE_READ_NOT_AUTHORIZED")
        | (
            "ERROR",
            "CALIBRATION_EVIDENCE_READ_AUTHORIZATION_UNAVAILABLE"
            | "CALIBRATION_EVIDENCE_READ_CAPACITY_UNAVAILABLE"
            | "CALIBRATION_EVIDENCE_READ_INTEGRITY_FAILED"
            | "CALIBRATION_EVIDENCE_READ_VAULT_UNAVAILABLE"
            | "CALIBRATION_EVIDENCE_READ_CANCELLED",
        ) => value.bytes_released.is_none(),
        _ => false,
    };
    if event.event_type != EVENT_TYPE
        || event.producer_id != PRODUCER_ID
        || event.policy_revision != POLICY_REVISION
        || event.request_id.is_some()
        || event.request_seq != 1
        || event.observed_at != event.occurred_at
        || event.trace_id != capability_trace
        || event.span_id != event_span[..16]
        || !event.evidence_refs.is_empty()
        || !event.cause_event_ids.is_empty()
        || event.sensitivity != "RESTRICTED"
        || value.stage != "calibration_evidence_read"
        || !valid_terminal
    {
        return Err(PublishError::InvalidEvent);
    }
    valid_prefixed_v7(&event.event_id, "ev_")?;
    valid_uuid_v7(&event.producer_boot_id)?;
    utc_millis(&event.occurred_at)?;
    Ok(PayloadSummary {
        stage: value.stage,
        outcome: value.outcome,
        reason_code: value.reason_code,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        // This is an audit result for an offline data release. It does not
        // express a protected-origin decision or a completed calibration job.
        ..PayloadSummary::default()
    })
}

fn utc_millis(value: &str) -> Result<(), PublishError> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| PublishError::InvalidEvent)?;
    if value.len() != 24
        || parsed.to_rfc3339_opts(SecondsFormat::Millis, true) != value
        || parsed.timestamp() < 0
        || parsed.timestamp_nanos_opt().is_none()
        // Chrono accepts RFC 3339 leap seconds; persisted journal clocks use
        // ordinary UTC seconds so the source byte is constrained after parsing.
        || value.as_bytes()[17] > b'5'
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(())
}
