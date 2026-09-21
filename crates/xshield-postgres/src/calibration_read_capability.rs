//! Durable issuance and recovery-safe leasing for calibration evidence batches.
//!
//! This adapter preserves a complete frozen catalog scope before it creates an
//! in-memory batch session. It neither opens a vault object nor interprets a
//! model record, a label, or a partition manifest. Console evidence access,
//! cases, and approvals deliberately do not participate in this authority.

use crate::{
    PostgresIdentityStore, StoreError,
    evidence_catalog::{CatalogArtifact, catalog_artifact},
};
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use openssl::{rand::rand_bytes, sha::sha256};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row, postgres::PgRow};
use std::{collections::BTreeMap, time::Duration};
use uuid::Uuid;
use xshield_core::{
    calibration::read_capability::{
        CalibrationEvidenceBatchCompletion, CalibrationEvidenceBatchLease,
        CalibrationEvidenceReadCapability, CalibrationEvidenceReadSession, CalibrationEvidenceRole,
    },
    domain::{CalibrationReadCapabilityId, CalibrationReadLeaseId, EventId, ModelRevision},
    identity::UnixSeconds,
    ports::{CalibrationEvidenceReadDenied, CalibrationEvidenceReadRequest},
};
use zeroize::Zeroizing;

const ISSUED_EVENT_TYPE: &str = "calibration.read_capability.issued";
const ISSUED_EVENT_REASON: &str = "CALIBRATION_READ_CAPABILITY_ISSUED";
const COMPLETED_EVENT_TYPE: &str = "calibration.read_batch.completed";
const COMPLETED_EVENT_REASON: &str = "CALIBRATION_READ_BATCH_COMPLETED";
const MAX_BATCH_LEASE_SECONDS: u64 = 3_600;
const MAX_RECOVERIES: i32 = 16;

/// Validated input for atomically issuing one frozen calibration-read capability.
pub struct CalibrationReadCapabilityIssue<'a> {
    capability: &'a CalibrationEvidenceReadCapability,
    issued_by: &'a str,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    event_id: &'a EventId,
}

impl<'a> CalibrationReadCapabilityIssue<'a> {
    /// Binds issuer retry material to a fully formed, purpose-limited capability.
    ///
    /// The constructor has no database, audit, vault, or model side effect. The
    /// caller must retain every argument unchanged when recovering an unknown
    /// transaction result.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when `issued_by` is not bounded
    /// text. Catalog availability and exact retry checks occur transactionally.
    pub fn new(
        capability: &'a CalibrationEvidenceReadCapability,
        issued_by: &'a str,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
        event_id: &'a EventId,
    ) -> Result<Self, StoreError> {
        if !valid_text(issued_by, 256) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            capability,
            issued_by,
            idempotency_digest,
            request_digest,
            event_id,
        })
    }
}

/// A bounded command to begin or recover one complete calibration batch.
pub struct CalibrationEvidenceBatchBegin<'a> {
    capability: &'a CalibrationEvidenceReadCapability,
    runner_id: &'a str,
    lease_for: Duration,
}

/// A bounded command to consume a lease after one complete evaluator succeeds.
///
/// The command deliberately accepts the core's
/// [`CalibrationEvidenceBatchCompletion`] rather than an artifact reference or
/// read request. That proof consumes the in-memory session and has already
/// checked the complete ordered evaluator source set; one successful object
/// open can therefore never consume a capability.
pub struct CalibrationEvidenceBatchComplete<'completion, 'capability> {
    completion: &'completion CalibrationEvidenceBatchCompletion<'capability>,
    runner_id: &'completion str,
}

impl<'completion, 'capability> CalibrationEvidenceBatchComplete<'completion, 'capability> {
    /// Binds the configured evaluator runner to its successful full-batch result.
    ///
    /// The runner must be the same configured evaluator identity that acquired
    /// the lease. Completion has no audit, report-publication, or vault I/O
    /// side effect; the adapter performs only the atomic lease-state change.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when `runner_id` is not bounded
    /// configured-runner text.
    pub fn new(
        completion: &'completion CalibrationEvidenceBatchCompletion<'capability>,
        runner_id: &'completion str,
    ) -> Result<Self, StoreError> {
        if !valid_text(runner_id, 128) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            completion,
            runner_id,
        })
    }
}

impl<'a> CalibrationEvidenceBatchBegin<'a> {
    /// Binds a trusted evaluator runner and whole-second lease duration.
    ///
    /// `runner_id` identifies a configured evaluator process, not a console
    /// subject or an approval authority. The database locks the frozen header,
    /// members, and live catalog rows before creating a lease.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for unbounded runner text or an
    /// invalid lease duration. No capability is issued or consumed here.
    pub fn new(
        capability: &'a CalibrationEvidenceReadCapability,
        runner_id: &'a str,
        lease_for: Duration,
    ) -> Result<Self, StoreError> {
        if !valid_text(runner_id, 128)
            || lease_for.as_secs() == 0
            || lease_for.as_secs() > MAX_BATCH_LEASE_SECONDS
            || lease_for.subsec_nanos() != 0
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            capability,
            runner_id,
            lease_for,
        })
    }
}

/// Public, non-secret durable metadata for one frozen capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationReadCapabilityRecord {
    capability_id: CalibrationReadCapabilityId,
    scope_digest: [u8; 32],
    member_count: u32,
    frozen_total_bytes: u64,
    not_before: UnixSeconds,
    expires_at: UnixSeconds,
    issued_at: DateTime<Utc>,
}

impl CalibrationReadCapabilityRecord {
    /// Returns the purpose-specific capability identity.
    #[must_use]
    pub const fn capability_id(&self) -> &CalibrationReadCapabilityId {
        &self.capability_id
    }

    /// Returns the SHA-256 of the canonical frozen scope representation.
    #[must_use]
    pub const fn scope_digest(&self) -> &[u8; 32] {
        &self.scope_digest
    }

    /// Returns the exact frozen artifact-role member count.
    #[must_use]
    pub const fn member_count(&self) -> u32 {
        self.member_count
    }

    /// Returns the catalog plaintext-byte total frozen at issuance.
    #[must_use]
    pub const fn frozen_total_bytes(&self) -> u64 {
        self.frozen_total_bytes
    }

    /// Returns the inclusive earliest batch time.
    #[must_use]
    pub const fn not_before(&self) -> UnixSeconds {
        self.not_before
    }

    /// Returns the exclusive capability deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Returns the database-assigned issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }
}

/// Result of an idempotent capability issuance transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalibrationReadCapabilityIssueOutcome {
    /// Header, members, and restricted outbox fact committed atomically.
    Issued(CalibrationReadCapabilityRecord),
    /// The exact frozen capability was committed by an earlier attempt.
    Existing(CalibrationReadCapabilityRecord),
    /// A capability ID or issuer idempotency key has different durable inputs.
    Conflict,
    /// A required catalog member is missing, inactive, expired, changed, or oversized.
    SourceUnavailable,
}

impl CalibrationReadCapabilityIssueOutcome {
    /// Returns the stable non-content terminal reason for caller-owned audit.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Issued(_) => ISSUED_EVENT_REASON,
            Self::Existing(_) => "CALIBRATION_READ_CAPABILITY_ALREADY_ISSUED",
            Self::Conflict => "CALIBRATION_READ_CAPABILITY_ISSUANCE_CONFLICT",
            Self::SourceUnavailable => "CALIBRATION_READ_CAPABILITY_SOURCE_UNAVAILABLE",
        }
    }
}

/// Result of trying to begin one capability-wide batch session.
pub enum CalibrationEvidenceBatchBeginOutcome {
    /// A unique, opaque lease may now be bound into the core read session.
    Started(CalibrationEvidenceBatchLease),
    /// Another evaluator still owns a live lease for this capability.
    Busy,
    /// The issued capability, its frozen members, or its lease window is unavailable.
    Unavailable,
    /// Recovery has reached its fixed durable retry bound.
    RecoveryExhausted,
}

/// Result of atomically consuming a capability-wide evaluator lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationEvidenceBatchCompleteOutcome {
    /// The active lease and its capability moved to their terminal states.
    Completed,
    /// This exact private lease had already completed in an earlier attempt.
    AlreadyCompleted,
    /// The exact capability, lease, catalog, or time window cannot complete.
    Unavailable,
}

impl CalibrationEvidenceBatchCompleteOutcome {
    /// Returns the stable non-content terminal reason for caller-owned audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Completed => "CALIBRATION_READ_BATCH_COMPLETED",
            Self::AlreadyCompleted => "CALIBRATION_READ_BATCH_ALREADY_COMPLETED",
            Self::Unavailable => "CALIBRATION_READ_BATCH_COMPLETION_UNAVAILABLE",
        }
    }
}

impl CalibrationEvidenceBatchBeginOutcome {
    /// Returns the stable non-content terminal reason for caller-owned audit.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Started(_) => "CALIBRATION_READ_BATCH_STARTED",
            Self::Busy => "CALIBRATION_READ_BATCH_BUSY",
            Self::Unavailable => "CALIBRATION_READ_BATCH_UNAVAILABLE",
            Self::RecoveryExhausted => "CALIBRATION_READ_BATCH_RECOVERY_EXHAUSTED",
        }
    }
}

/// A storage-authorized calibration artifact ready for vault-side authentication.
///
/// This is not content and cannot be constructed by an evaluator. It carries
/// the exact catalog manifest and semantic role observed in the same locked
/// transaction that verified the durable capability and lease. A vault reader
/// must still authenticate its local manifest, compare it to this catalog
/// record, and verify ciphertext digest and AEAD before releasing plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCalibrationEvidence {
    artifact: CatalogArtifact,
    role: CalibrationEvidenceRole,
    sample_index: Option<u16>,
}

impl AuthorizedCalibrationEvidence {
    /// Returns the authenticated catalog expectation for the vault reader.
    #[must_use]
    pub const fn artifact(&self) -> &CatalogArtifact {
        &self.artifact
    }

    /// Returns the frozen semantic role under which this object may be read.
    #[must_use]
    pub const fn role(&self) -> CalibrationEvidenceRole {
        self.role
    }

    /// Returns the frozen sample slot, absent for the four manifests.
    #[must_use]
    pub const fn sample_index(&self) -> Option<u16> {
        self.sample_index
    }
}

/// Closed result of revalidating one calibration evidence read at the database boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalibrationEvidenceReadAuthorizationOutcome {
    /// The exact current catalog artifact may proceed to vault authentication.
    Authorized(Box<AuthorizedCalibrationEvidence>),
    /// The capability, lease, member, or live catalog cannot authorize content.
    Denied(CalibrationEvidenceReadDenied),
}

impl PostgresIdentityStore {
    /// Issues one exact frozen calibration capability with its restricted audit fact.
    ///
    /// New issuance takes deterministic catalog row locks, freezes the exact
    /// catalog snapshots and aggregate byte count, inserts every member, and
    /// inserts one small outbox fact in the same transaction. A retry compares
    /// only durable frozen state, so later catalog changes cannot alter or
    /// silently replace an already issued batch.
    ///
    /// # Errors
    /// Returns [`StoreError`] for malformed durable state, entropy failure, or
    /// database failure. It never opens evidence, calls a model, or creates a
    /// console approval.
    pub async fn issue_calibration_read_capability(
        &self,
        command: CalibrationReadCapabilityIssue<'_>,
    ) -> Result<CalibrationReadCapabilityIssueOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_short_timeouts(&mut transaction).await?;
        lock_issuer(&mut transaction, &command).await?;
        lock_capability(&mut transaction, command.capability).await?;

        if let Some(row) = find_capability(&mut transaction, command.capability).await? {
            let outcome = existing_issue_outcome(&mut transaction, &row, &command).await?;
            transaction.rollback().await?;
            return Ok(outcome);
        }
        if issuer_idempotency_is_used(&mut transaction, &command).await? {
            transaction.rollback().await?;
            return Ok(CalibrationReadCapabilityIssueOutcome::Conflict);
        }

        let capability_expires_at = unix_timestamp(command.capability.expires_at())?;
        let snapshots = lock_current_catalog(&mut transaction, command.capability).await?;
        if snapshots.len() != command.capability.evidence_refs().len() {
            transaction.rollback().await?;
            return Ok(CalibrationReadCapabilityIssueOutcome::SourceUnavailable);
        }
        let frozen_total_bytes = snapshots.values().try_fold(0_u64, |total, snapshot| {
            total
                .checked_add(snapshot.bytes_saved)
                .ok_or(StoreError::NumericRange("frozen_total_bytes"))
        })?;
        if frozen_total_bytes > command.capability.max_total_bytes() {
            transaction.rollback().await?;
            return Ok(CalibrationReadCapabilityIssueOutcome::SourceUnavailable);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        if now >= capability_expires_at {
            transaction.rollback().await?;
            return Ok(CalibrationReadCapabilityIssueOutcome::SourceUnavailable);
        }
        let members = freeze_members(command.capability, &snapshots)?;
        let scope_digest = scope_digest(command.capability, &members);
        let record = insert_capability_header(
            &mut transaction,
            &command,
            &scope_digest,
            frozen_total_bytes,
        )
        .await?;
        insert_members(&mut transaction, command.capability, &members).await?;
        insert_issuance_event(&mut transaction, &command, &record).await?;
        transaction.commit().await?;
        Ok(CalibrationReadCapabilityIssueOutcome::Issued(record))
    }

    /// Atomically claims a full frozen capability or advances a declared recovery.
    ///
    /// The database rechecks the durable capability shape, all member snapshots,
    /// and live catalog rows under lock before it creates a fresh token digest.
    /// A valid result contains the plaintext token only in its non-cloneable
    /// in-memory handle; `PostgreSQL` stores its SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`StoreError`] for corrupt durable state, entropy failure, or
    /// database failure. This operation has no vault or model side effect.
    #[allow(clippy::too_many_lines)]
    pub async fn begin_calibration_evidence_batch(
        &self,
        command: CalibrationEvidenceBatchBegin<'_>,
    ) -> Result<CalibrationEvidenceBatchBeginOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_short_timeouts(&mut transaction).await?;
        let Some(header) = find_capability(&mut transaction, command.capability).await? else {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
        };
        if !durable_capability_matches(&mut transaction, &header, command.capability).await? {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        let not_before = unix_timestamp(command.capability.not_before())?;
        let capability_expires_at = unix_timestamp(command.capability.expires_at())?;
        if now < not_before {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
        }
        if now >= capability_expires_at {
            expire_capability_if_needed(&mut transaction, &header, now).await?;
            transaction.commit().await?;
            return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
        }
        if !members_match_live_catalog(&mut transaction, command.capability, &header).await? {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
        }

        let recovery = resolve_live_or_recovery(&mut transaction, &header, now).await?;
        let (generation, expected_header_status) = match recovery {
            LeasePreparation::Start => (1, "issued"),
            LeasePreparation::Busy => {
                transaction.rollback().await?;
                return Ok(CalibrationEvidenceBatchBeginOutcome::Busy);
            }
            LeasePreparation::RecoveryExhausted => {
                transaction.commit().await?;
                return Ok(CalibrationEvidenceBatchBeginOutcome::RecoveryExhausted);
            }
            LeasePreparation::Recover { generation } => (generation, "recovery_required"),
            LeasePreparation::Unavailable => {
                transaction.rollback().await?;
                return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
            }
        };
        let requested_seconds = i64::try_from(command.lease_for.as_secs())
            .map_err(|_| StoreError::NumericRange("lease_for"))?;
        let lease_until: DateTime<Utc> = sqlx::query_scalar(
            "SELECT LEAST($1::timestamptz, date_trunc('milliseconds', clock_timestamp())
                    + make_interval(secs => $2::double precision))",
        )
        .bind(capability_expires_at)
        .bind(requested_seconds)
        .fetch_one(&mut *transaction)
        .await?;
        let acquired_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
                .fetch_one(&mut *transaction)
                .await?;
        if lease_until <= acquired_at {
            expire_capability_if_needed(&mut transaction, &header, acquired_at).await?;
            transaction.commit().await?;
            return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
        }
        let lease_id = CalibrationReadLeaseId::parse(format!("callease_{}", Uuid::now_v7()))
            .map_err(|_| StoreError::InvalidCommand)?;
        let mut token = Zeroizing::new([0_u8; 32]);
        rand_bytes(token.as_mut()).map_err(|_| StoreError::Entropy)?;
        let token_digest = sha256(token.as_ref());
        insert_lease(
            &mut transaction,
            command.capability,
            command.runner_id,
            &lease_id,
            generation,
            &token_digest,
            acquired_at,
            lease_until,
        )
        .await?;
        let recovery_attempts = generation - 1;
        let changed = sqlx::query(
            "UPDATE xshield.calibration_read_capabilities
             SET status='leased', lease_generation=$4, recovery_attempts=$5,
                 recovery_required_at=NULL
             WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND status=$6",
        )
        .bind(command.capability.tenant_id().as_str())
        .bind(command.capability.site_id().as_str())
        .bind(command.capability.capability_id().as_str())
        .bind(generation)
        .bind(recovery_attempts)
        .bind(expected_header_status)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::CorruptData("calibration_leasing_header"));
        }
        let still_live: bool = sqlx::query_scalar("SELECT $1::timestamptz > clock_timestamp()")
            .bind(lease_until)
            .fetch_one(&mut *transaction)
            .await?;
        if !still_live {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchBeginOutcome::Unavailable);
        }
        transaction.commit().await?;

        let core_not_before = u64::try_from(acquired_at.timestamp())
            .map_err(|_| StoreError::CorruptData("lease_acquired_at"))?;
        let core_expires_at = u64::try_from(lease_until.timestamp())
            .map_err(|_| StoreError::CorruptData("lease_until"))?;
        let lease = CalibrationEvidenceBatchLease::from_issued(
            lease_id,
            command.capability.capability_id().clone(),
            command.capability.tenant_id().clone(),
            command.capability.site_id().clone(),
            UnixSeconds::new(core_not_before),
            UnixSeconds::new(core_expires_at),
            *token,
        )
        .map_err(|_| StoreError::CorruptData("issued_calibration_lease"))?;
        Ok(CalibrationEvidenceBatchBeginOutcome::Started(lease))
    }

    /// Atomically consumes an active lease after a complete evaluator succeeds.
    ///
    /// The core completion proof binds the in-memory lease to an
    /// [`EvaluationReport`](xshield_core::calibration::dataset::EvaluationReport)
    /// whose provenance and ordered source pairs exactly match the frozen
    /// capability. This transaction rechecks that immutable durable snapshot,
    /// the live catalog, configured runner, active lease ID, and private token
    /// digest before it updates `active -> completed` and `leased -> consumed`.
    /// A single artifact authorization or vault read has no path to this state
    /// transition. Repeating the same completed private lease is safe after an
    /// unknown commit result; it does not reopen or reconsume the capability.
    ///
    /// This operation writes a restricted, content-free completion outbox fact
    /// in the same transaction as the two state transitions. It does not write
    /// a generic `evidence.read` record: the reader owns the separate
    /// pre-plaintext audit, and a later report producer owns its distinct
    /// report/audit transaction. Neither journal/index state is authorization
    /// truth for this transition.
    ///
    /// # Errors
    /// Returns [`StoreError`] for a database or corrupt durable-state failure.
    /// Expected mismatches, expiration, revocation, catalog drift, or a lease
    /// held by another runner return [`CalibrationEvidenceBatchCompleteOutcome::Unavailable`]
    /// without exposing content.
    pub async fn complete_calibration_evidence_batch(
        &self,
        command: CalibrationEvidenceBatchComplete<'_, '_>,
    ) -> Result<CalibrationEvidenceBatchCompleteOutcome, StoreError> {
        let completion = command.completion;
        let session = completion.session();
        let capability = session.capability();
        let mut transaction = self.pool.begin().await?;
        set_short_timeouts(&mut transaction).await?;
        let Some(header) = find_capability(&mut transaction, capability).await? else {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchCompleteOutcome::Unavailable);
        };
        let header_status: &str = header.try_get("status")?;
        if header_status == "consumed" {
            let completed =
                completed_lease_matches(&mut transaction, capability, session, command.runner_id)
                    .await?;
            let audited =
                completed && completion_event_exists(&mut transaction, &header, capability).await?;
            transaction.rollback().await?;
            if completed && !audited {
                return Err(StoreError::CorruptData("calibration_completion_outbox"));
            }
            return Ok(if completed {
                CalibrationEvidenceBatchCompleteOutcome::AlreadyCompleted
            } else {
                CalibrationEvidenceBatchCompleteOutcome::Unavailable
            });
        }
        if !durable_capability_matches(&mut transaction, &header, capability).await? {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchCompleteOutcome::Unavailable);
        }
        if header_status != "leased" {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchCompleteOutcome::Unavailable);
        }

        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        let not_before = unix_timestamp(capability.not_before())?;
        let capability_expires_at = unix_timestamp(capability.expires_at())?;
        if now < not_before {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchCompleteOutcome::Unavailable);
        }
        if now >= capability_expires_at {
            expire_capability_if_needed(&mut transaction, &header, now).await?;
            transaction.commit().await?;
            return Ok(CalibrationEvidenceBatchCompleteOutcome::Unavailable);
        }
        if !members_match_live_catalog(&mut transaction, capability, &header).await? {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchCompleteOutcome::Unavailable);
        }
        if !active_lease_matches_completion(
            &mut transaction,
            &header,
            capability,
            session,
            command.runner_id,
            now,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationEvidenceBatchCompleteOutcome::Unavailable);
        }
        complete_active_calibration_batch(
            &mut transaction,
            capability,
            session,
            command.runner_id,
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(CalibrationEvidenceBatchCompleteOutcome::Completed)
    }

    /// Revalidates one exact capability member immediately before vault access.
    ///
    /// This authorization is deliberately purpose-specific: it verifies the
    /// private in-memory lease token against its durable digest, locks the
    /// header, every frozen member, and every live catalog row, and checks the
    /// complete frozen scope before selecting the requested member. It neither
    /// opens evidence, consumes the batch, writes an audit event, nor treats a
    /// console approval as equivalent authority.
    ///
    /// # Errors
    /// Returns [`StoreError`] for a database or corrupt durable-state failure.
    /// Expected expired, revoked, mismatched, or unavailable authority returns
    /// the closed [`CalibrationEvidenceReadAuthorizationOutcome::Denied`]
    /// result so callers cannot distinguish artifact existence.
    pub async fn authorize_calibration_evidence_read(
        &self,
        request: &CalibrationEvidenceReadRequest<'_>,
    ) -> Result<CalibrationEvidenceReadAuthorizationOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_short_timeouts(&mut transaction).await?;
        let denied = || {
            CalibrationEvidenceReadAuthorizationOutcome::Denied(
                CalibrationEvidenceReadDenied::EvidenceNotAuthorized,
            )
        };

        let Some(header) = find_capability(&mut transaction, request.capability()).await? else {
            transaction.rollback().await?;
            return Ok(denied());
        };
        if !durable_capability_matches(&mut transaction, &header, request.capability()).await? {
            transaction.rollback().await?;
            return Ok(denied());
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        let Some(lease) =
            active_lease_matches_request(&mut transaction, &header, request, now).await?
        else {
            transaction.rollback().await?;
            return Ok(denied());
        };
        if !members_match_live_catalog(&mut transaction, request.capability(), &header).await? {
            transaction.rollback().await?;
            return Ok(denied());
        }
        let Some(authorized) =
            authorized_member_for_request(&mut transaction, request, lease).await?
        else {
            transaction.rollback().await?;
            return Ok(denied());
        };
        transaction.commit().await?;
        Ok(CalibrationEvidenceReadAuthorizationOutcome::Authorized(
            Box::new(authorized),
        ))
    }
}

#[derive(Clone)]
struct CatalogSnapshot {
    artifact_id: String,
    bytes_saved: u64,
    integrity_digest: String,
    kind: String,
    content_type: String,
    fidelity: String,
    classification: String,
    expires_at: DateTime<Utc>,
    catalog_event_id: String,
}

struct FrozenMember {
    role: CalibrationEvidenceRole,
    sample_index: Option<u16>,
    snapshot: CatalogSnapshot,
}

enum LeasePreparation {
    Start,
    Busy,
    Recover { generation: i32 },
    RecoveryExhausted,
    Unavailable,
}

/// Performs the two durable state changes and their inseparable terminal fact.
/// The caller has already locked and revalidated the capability, member set,
/// and active lease, so a mismatch here is durable corruption rather than a
/// caller-visible authorization denial.
async fn complete_active_calibration_batch(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
    session: &CalibrationEvidenceReadSession<'_>,
    runner_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let completed_at = date_millis(now);
    let token_digest = sha256(session.lease().token());
    let lease_changed = sqlx::query(
        "UPDATE xshield.calibration_read_capability_leases
         SET status='completed', completed_at=$6
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4
           AND runner_id=$5 AND status='active' AND lease_token_digest=$7",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(session.lease().lease_id().as_str())
    .bind(runner_id)
    .bind(completed_at)
    .bind(token_digest.as_slice())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if lease_changed != 1 {
        return Err(StoreError::CorruptData("calibration_completing_lease"));
    }
    let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7()))
        .map_err(|_| StoreError::CorruptData("calibration_completion_event_id"))?;
    let header_changed = sqlx::query(
        "UPDATE xshield.calibration_read_capabilities
         SET status='consumed', consumed_at=$4, recovery_required_at=NULL,
             completion_event_id=$5
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND status='leased'",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(completed_at)
    .bind(event_id.as_str())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if header_changed != 1 {
        return Err(StoreError::CorruptData("calibration_consuming_header"));
    }
    insert_completion_event(connection, &event_id, capability, completed_at).await
}

async fn set_short_timeouts(connection: &mut PgConnection) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut *connection)
        .await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn lock_issuer(
    connection: &mut PgConnection,
    command: &CalibrationReadCapabilityIssue<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            'xshield-calibration-read-issue-v1:' || $1 || ':' || $2 || ':' || $3, 0
         ))",
    )
    .bind(command.capability.tenant_id().as_str())
    .bind(command.capability.site_id().as_str())
    .bind(command.issued_by)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// Serializes attempts for one capability before the row exists.
///
/// The issuer-scoped lock protects an issuer's idempotency key, but two
/// distinct issuers may name the same capability. Locking the immutable
/// capability ID makes the second transaction re-read the committed header
/// and return its stable conflict outcome instead of leaking a unique-key
/// race through the storage error boundary.
async fn lock_capability(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
) -> Result<(), StoreError> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            'xshield-calibration-read-capability-v1:' || $1, 0
         ))",
    )
    .bind(capability.capability_id().as_str())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn find_capability(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
) -> Result<Option<PgRow>, StoreError> {
    Ok(sqlx::query(
        "SELECT * FROM xshield.calibration_read_capabilities
         WHERE capability_id=$1 FOR UPDATE",
    )
    .bind(capability.capability_id().as_str())
    .fetch_optional(&mut *connection)
    .await?)
}

async fn issuer_idempotency_is_used(
    connection: &mut PgConnection,
    command: &CalibrationReadCapabilityIssue<'_>,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM xshield.calibration_read_capabilities
         WHERE tenant_id=$1 AND site_id=$2 AND issued_by=$3
           AND issuance_idempotency_digest=$4
         FOR UPDATE",
    )
    .bind(command.capability.tenant_id().as_str())
    .bind(command.capability.site_id().as_str())
    .bind(command.issued_by)
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(&mut *connection)
    .await?
    .is_some())
}

async fn existing_issue_outcome(
    connection: &mut PgConnection,
    row: &PgRow,
    command: &CalibrationReadCapabilityIssue<'_>,
) -> Result<CalibrationReadCapabilityIssueOutcome, StoreError> {
    if !header_matches_command(row, command)? {
        return Ok(CalibrationReadCapabilityIssueOutcome::Conflict);
    }
    let Some(members) = frozen_members_for_capability(connection, row, command.capability).await?
    else {
        return Ok(CalibrationReadCapabilityIssueOutcome::Conflict);
    };
    if !frozen_scope_matches(row, command.capability, &members)? {
        return Ok(CalibrationReadCapabilityIssueOutcome::Conflict);
    }
    let record = record_from_header(row)?;
    let envelope = issuance_event(command.event_id, command.capability, &record)?;
    let audited: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM xshield.audit_outbox
             WHERE event_id=$1 AND tenant_id=$2 AND site_id=$3
               AND aggregate_ref=$4 AND event_type=$5 AND envelope=$6
         )",
    )
    .bind(command.event_id.as_str())
    .bind(command.capability.tenant_id().as_str())
    .bind(command.capability.site_id().as_str())
    .bind(command.capability.capability_id().as_str())
    .bind(ISSUED_EVENT_TYPE)
    .bind(envelope)
    .fetch_one(&mut *connection)
    .await?;
    if !audited {
        return Err(StoreError::CorruptData("calibration_capability_outbox"));
    }
    Ok(CalibrationReadCapabilityIssueOutcome::Existing(record))
}

fn header_matches_command(
    row: &PgRow,
    command: &CalibrationReadCapabilityIssue<'_>,
) -> Result<bool, StoreError> {
    if !header_matches_capability(row, command.capability)? {
        return Ok(false);
    }
    let equal = row.try_get::<&str, _>("issued_by")? == command.issued_by
        && row
            .try_get::<Vec<u8>, _>("issuance_idempotency_digest")?
            .as_slice()
            == command.idempotency_digest
        && row
            .try_get::<Vec<u8>, _>("issuance_request_digest")?
            .as_slice()
            == command.request_digest
        && row.try_get::<&str, _>("issued_event_id")? == command.event_id.as_str();
    Ok(equal)
}

fn header_matches_capability(
    row: &PgRow,
    capability: &CalibrationEvidenceReadCapability,
) -> Result<bool, StoreError> {
    let model = capability.provenance().model();
    let equal = row.try_get::<&str, _>("tenant_id")? == capability.tenant_id().as_str()
        && row.try_get::<&str, _>("site_id")? == capability.site_id().as_str()
        && row.try_get::<&str, _>("capability_id")? == capability.capability_id().as_str()
        && row.try_get::<&str, _>("approval_ref")?
            == capability.provenance().approval_ref().as_str()
        && row.try_get::<&str, _>("dataset_revision")?
            == capability.provenance().dataset_revision().as_str()
        && row.try_get::<&str, _>("label_revision")?
            == capability.provenance().label_revision().as_str()
        && row.try_get::<&str, _>("task_revision")?
            == capability.provenance().task_revision().as_str()
        && row.try_get::<&str, _>("threshold_policy_revision")?
            == capability.provenance().threshold_policy_revision().as_str()
        && row.try_get::<&str, _>("mapping_revision")?
            == capability.provenance().mapping_revision().as_str()
        && row.try_get::<&str, _>("provider")? == model.provider().as_str()
        && row.try_get::<&str, _>("provider_model_id")? == model.provider_model_id()
        && row.try_get::<&str, _>("model_revision")? == model.model_revision().as_str()
        && row.try_get::<&str, _>("prompt_revision")? == model.prompt_revision().as_str()
        && row.try_get::<Option<&str>, _>("resolved_model_revision")?
            == model.resolved_model_revision().map(ModelRevision::as_str)
        && row.try_get::<DateTime<Utc>, _>("not_before")?
            == unix_timestamp(capability.not_before())?
        && row.try_get::<DateTime<Utc>, _>("expires_at")?
            == unix_timestamp(capability.expires_at())?
        && row.try_get::<i64, _>("max_total_bytes")?
            == i64::try_from(capability.max_total_bytes())
                .map_err(|_| StoreError::NumericRange("max_total_bytes"))?
        && row.try_get::<i32, _>("sample_count")?
            == i32::try_from(capability.sources().len())
                .map_err(|_| StoreError::NumericRange("sample_count"))?
        && row.try_get::<i32, _>("member_count")?
            == i32::try_from(capability.evidence_refs().len())
                .map_err(|_| StoreError::NumericRange("member_count"))?;
    Ok(equal)
}

async fn lock_current_catalog(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
) -> Result<BTreeMap<String, CatalogSnapshot>, StoreError> {
    let refs = capability.evidence_refs();
    let mut artifact_ids = refs
        .iter()
        .map(|reference| reference.artifact_id().as_str().to_owned())
        .collect::<Vec<_>>();
    artifact_ids.sort_unstable();
    let rows = sqlx::query(
        "SELECT artifact_id, bytes_saved, integrity_digest, kind, content_type,
                fidelity, classification, expires_at, catalog_event_id, status, deleted_at
         FROM xshield.artifact_catalog
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=ANY($3)
         ORDER BY artifact_id
         FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(artifact_ids)
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() != refs.len() {
        return Ok(BTreeMap::new());
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *connection)
        .await?;
    let end = unix_timestamp(capability.expires_at())?;
    let mut snapshots = BTreeMap::new();
    for row in rows {
        let status: &str = row.try_get("status")?;
        let deleted_at: Option<DateTime<Utc>> = row.try_get("deleted_at")?;
        let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
        if status != "active" || deleted_at.is_some() || expires_at <= now || expires_at < end {
            return Ok(BTreeMap::new());
        }
        let bytes_saved = u64::try_from(row.try_get::<i64, _>("bytes_saved")?)
            .map_err(|_| StoreError::CorruptData("catalog_bytes_saved"))?;
        let snapshot = CatalogSnapshot {
            artifact_id: row.try_get("artifact_id")?,
            bytes_saved,
            integrity_digest: row.try_get("integrity_digest")?,
            kind: row.try_get("kind")?,
            content_type: row.try_get("content_type")?,
            fidelity: row.try_get("fidelity")?,
            classification: row.try_get("classification")?,
            expires_at,
            catalog_event_id: row.try_get("catalog_event_id")?,
        };
        if snapshots
            .insert(snapshot.artifact_id.clone(), snapshot)
            .is_some()
        {
            return Err(StoreError::CorruptData("duplicate_catalog_artifact"));
        }
    }
    Ok(snapshots)
}

fn freeze_members(
    capability: &CalibrationEvidenceReadCapability,
    snapshots: &BTreeMap<String, CatalogSnapshot>,
) -> Result<Vec<FrozenMember>, StoreError> {
    capability
        .evidence_refs()
        .into_iter()
        .map(|reference| {
            let snapshot = snapshots
                .get(reference.artifact_id().as_str())
                .ok_or(StoreError::InvalidCommand)?
                .clone();
            Ok(FrozenMember {
                role: reference.role(),
                sample_index: reference.sample_index(),
                snapshot,
            })
        })
        .collect()
}

fn scope_digest(
    capability: &CalibrationEvidenceReadCapability,
    members: &[FrozenMember],
) -> [u8; 32] {
    let mut canonical = Vec::with_capacity(4096);
    append_field(
        &mut canonical,
        "xshield-calibration-read-capability-scope-v1",
    );
    append_field(&mut canonical, capability.tenant_id().as_str());
    append_field(&mut canonical, capability.site_id().as_str());
    append_field(&mut canonical, &capability.not_before().value().to_string());
    append_field(&mut canonical, &capability.expires_at().value().to_string());
    append_field(&mut canonical, &capability.max_total_bytes().to_string());
    let provenance = capability.provenance();
    for field in [
        provenance.approval_ref().as_str(),
        provenance.dataset_revision().as_str(),
        provenance.label_revision().as_str(),
        provenance.task_revision().as_str(),
        provenance.threshold_policy_revision().as_str(),
        provenance.mapping_revision().as_str(),
        provenance.evaluation_manifest_artifact_id().as_str(),
        provenance.training_manifest_artifact_id().as_str(),
        provenance.calibration_manifest_artifact_id().as_str(),
        provenance.label_manifest_artifact_id().as_str(),
        provenance.model().provider().as_str(),
        provenance.model().provider_model_id(),
        provenance.model().model_revision().as_str(),
        provenance.model().prompt_revision().as_str(),
        provenance
            .model()
            .resolved_model_revision()
            .map_or("", |revision| revision.as_str()),
    ] {
        append_field(&mut canonical, field);
    }
    for member in members {
        append_field(&mut canonical, member.role.as_str());
        append_field(
            &mut canonical,
            &member
                .sample_index
                .map_or_else(|| "-".to_owned(), |index| index.to_string()),
        );
        append_field(&mut canonical, &member.snapshot.artifact_id);
        append_field(&mut canonical, &member.snapshot.bytes_saved.to_string());
        append_field(&mut canonical, &member.snapshot.integrity_digest);
        append_field(
            &mut canonical,
            &member.snapshot.expires_at.timestamp_micros().to_string(),
        );
        append_field(&mut canonical, &member.snapshot.catalog_event_id);
        append_field(&mut canonical, &member.snapshot.kind);
        append_field(&mut canonical, &member.snapshot.content_type);
        append_field(&mut canonical, &member.snapshot.fidelity);
        append_field(&mut canonical, &member.snapshot.classification);
    }
    sha256(&canonical)
}

fn append_field(target: &mut Vec<u8>, value: &str) {
    let length = value.len() as u64;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}

async fn insert_capability_header(
    connection: &mut PgConnection,
    command: &CalibrationReadCapabilityIssue<'_>,
    scope_digest: &[u8; 32],
    frozen_total_bytes: u64,
) -> Result<CalibrationReadCapabilityRecord, StoreError> {
    let capability = command.capability;
    let provenance = capability.provenance();
    let model = provenance.model();
    let row = sqlx::query(
        "INSERT INTO xshield.calibration_read_capabilities (
             tenant_id, site_id, capability_id, approval_ref, dataset_revision,
             label_revision, task_revision, threshold_policy_revision, mapping_revision,
             provider, provider_model_id, model_revision, prompt_revision,
             resolved_model_revision, scope_digest, sample_count, member_count,
             max_total_bytes, frozen_total_bytes, not_before, expires_at, issued_by,
             issuance_idempotency_digest, issuance_request_digest, issued_event_id,
             issued_at, status
         ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
             to_timestamp($20),to_timestamp($21),$22,$23,$24,$25,
             date_trunc('milliseconds', clock_timestamp()),'issued'
         ) RETURNING *",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(provenance.approval_ref().as_str())
    .bind(provenance.dataset_revision().as_str())
    .bind(provenance.label_revision().as_str())
    .bind(provenance.task_revision().as_str())
    .bind(provenance.threshold_policy_revision().as_str())
    .bind(provenance.mapping_revision().as_str())
    .bind(model.provider().as_str())
    .bind(model.provider_model_id())
    .bind(model.model_revision().as_str())
    .bind(model.prompt_revision().as_str())
    .bind(model.resolved_model_revision().map(ModelRevision::as_str))
    .bind(scope_digest.as_slice())
    .bind(
        i32::try_from(capability.sources().len())
            .map_err(|_| StoreError::NumericRange("sample_count"))?,
    )
    .bind(
        i32::try_from(capability.evidence_refs().len())
            .map_err(|_| StoreError::NumericRange("member_count"))?,
    )
    .bind(
        i64::try_from(capability.max_total_bytes())
            .map_err(|_| StoreError::NumericRange("max_total_bytes"))?,
    )
    .bind(
        i64::try_from(frozen_total_bytes)
            .map_err(|_| StoreError::NumericRange("frozen_total_bytes"))?,
    )
    .bind(
        i64::try_from(capability.not_before().value())
            .map_err(|_| StoreError::NumericRange("not_before"))?,
    )
    .bind(
        i64::try_from(capability.expires_at().value())
            .map_err(|_| StoreError::NumericRange("expires_at"))?,
    )
    .bind(command.issued_by)
    .bind(command.idempotency_digest.as_slice())
    .bind(command.request_digest.as_slice())
    .bind(command.event_id.as_str())
    .fetch_one(&mut *connection)
    .await?;
    record_from_header(&row)
}

async fn insert_members(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
    members: &[FrozenMember],
) -> Result<(), StoreError> {
    for member in members {
        sqlx::query(
            "INSERT INTO xshield.calibration_read_capability_members (
                 tenant_id, site_id, capability_id, artifact_id, role, sample_index,
                 catalog_bytes_saved, catalog_integrity_digest, catalog_kind,
                 catalog_content_type, catalog_fidelity, catalog_classification,
                 catalog_expires_at, catalog_event_id
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(capability.tenant_id().as_str())
        .bind(capability.site_id().as_str())
        .bind(capability.capability_id().as_str())
        .bind(&member.snapshot.artifact_id)
        .bind(member.role.as_str())
        .bind(member.sample_index.map(i32::from))
        .bind(
            i64::try_from(member.snapshot.bytes_saved)
                .map_err(|_| StoreError::NumericRange("catalog_bytes_saved"))?,
        )
        .bind(&member.snapshot.integrity_digest)
        .bind(&member.snapshot.kind)
        .bind(&member.snapshot.content_type)
        .bind(&member.snapshot.fidelity)
        .bind(&member.snapshot.classification)
        .bind(member.snapshot.expires_at)
        .bind(&member.snapshot.catalog_event_id)
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

async fn insert_issuance_event(
    connection: &mut PgConnection,
    command: &CalibrationReadCapabilityIssue<'_>,
    record: &CalibrationReadCapabilityRecord,
) -> Result<(), StoreError> {
    let envelope = issuance_event(command.event_id, command.capability, record)?;
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
             event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(command.event_id.as_str())
    .bind(command.capability.tenant_id().as_str())
    .bind(command.capability.site_id().as_str())
    .bind(command.capability.capability_id().as_str())
    .bind(ISSUED_EVENT_TYPE)
    .bind(envelope)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// Inserts the durable batch-consumption terminal without source references,
/// lease material, evaluator output, or a report claim.
async fn insert_completion_event(
    connection: &mut PgConnection,
    event_id: &EventId,
    capability: &CalibrationEvidenceReadCapability,
    completed_at: DateTime<Utc>,
) -> Result<(), StoreError> {
    let envelope = completion_event(event_id, capability, completed_at)?;
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
             event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(event_id.as_str())
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(COMPLETED_EVENT_TYPE)
    .bind(envelope)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn issuance_event(
    event_id: &EventId,
    capability: &CalibrationEvidenceReadCapability,
    record: &CalibrationReadCapabilityRecord,
) -> Result<Value, StoreError> {
    let trace_id = capability
        .capability_id()
        .as_str()
        .strip_prefix("calcap_")
        .ok_or(StoreError::CorruptData("capability_id"))?
        .replace('-', "");
    let timestamp = record
        .issued_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    if trace_id.len() != 32 || timestamp.len() != 24 {
        return Err(StoreError::CorruptData("calibration_capability_event"));
    }
    Ok(json!({
        "schema_version": 3, "event_id": event_id.as_str(), "event_type": ISSUED_EVENT_TYPE,
        "tenant_id": capability.tenant_id().as_str(), "site_id": capability.site_id().as_str(),
        "request_id": null, "trace_id": trace_id, "span_id": &trace_id[..16],
        "producer_id": "calibration-capability-issuer", "producer_boot_id": event_id.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": timestamp, "observed_at": timestamp,
        "policy_revision": "calibration-v1", "example_only": false,
        "evidence_refs": [], "cause_event_ids": [], "sensitivity": "RESTRICTED",
        "integrity": {"state":"pending", "previous_hash":null, "event_hash":null},
        "payload": {
            "stage":"calibration_read_capability", "outcome":"PASS",
            "reason_code":ISSUED_EVENT_REASON,
            "capability_id": capability.capability_id().as_str(),
            "scope_digest": lower_hex(record.scope_digest()),
            "member_count": record.member_count(),
            "frozen_total_bytes": record.frozen_total_bytes(),
            "not_before_unix": record.not_before().value(),
            "expires_at_unix": record.expires_at().value()
        }
    }))
}

fn completion_event(
    event_id: &EventId,
    capability: &CalibrationEvidenceReadCapability,
    completed_at: DateTime<Utc>,
) -> Result<Value, StoreError> {
    let trace_id = capability
        .capability_id()
        .as_str()
        .strip_prefix("calcap_")
        .ok_or(StoreError::CorruptData("capability_id"))?
        .replace('-', "");
    let timestamp = completed_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    if trace_id.len() != 32 || timestamp.len() != 24 {
        return Err(StoreError::CorruptData("calibration_completion_event"));
    }
    Ok(json!({
        "schema_version": 3, "event_id": event_id.as_str(), "event_type": COMPLETED_EVENT_TYPE,
        "tenant_id": capability.tenant_id().as_str(), "site_id": capability.site_id().as_str(),
        "request_id": null, "trace_id": trace_id, "span_id": &trace_id[..16],
        "producer_id": "calibration-evidence-batch-completer", "producer_boot_id": event_id.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": timestamp, "observed_at": timestamp,
        "policy_revision": "calibration-v1", "example_only": false,
        "evidence_refs": [], "cause_event_ids": [], "sensitivity": "RESTRICTED",
        "integrity": {"state":"pending", "previous_hash":null, "event_hash":null},
        "payload": {
            "stage":"calibration_read_batch", "outcome":"PASS",
            "reason_code":COMPLETED_EVENT_REASON,
            "capability_id": capability.capability_id().as_str()
        }
    }))
}

fn record_from_header(row: &PgRow) -> Result<CalibrationReadCapabilityRecord, StoreError> {
    let scope_digest: [u8; 32] = row
        .try_get::<Vec<u8>, _>("scope_digest")?
        .try_into()
        .map_err(|_| StoreError::CorruptData("calibration_scope_digest"))?;
    let not_before = unix_seconds(row.try_get("not_before")?, "calibration_not_before")?;
    let expires_at = unix_seconds(row.try_get("expires_at")?, "calibration_expires_at")?;
    Ok(CalibrationReadCapabilityRecord {
        capability_id: CalibrationReadCapabilityId::parse(row.try_get::<&str, _>("capability_id")?)
            .map_err(|_| StoreError::CorruptData("calibration_capability_id"))?,
        scope_digest,
        member_count: u32::try_from(row.try_get::<i32, _>("member_count")?)
            .map_err(|_| StoreError::CorruptData("calibration_member_count"))?,
        frozen_total_bytes: u64::try_from(row.try_get::<i64, _>("frozen_total_bytes")?)
            .map_err(|_| StoreError::CorruptData("calibration_frozen_total_bytes"))?,
        not_before,
        expires_at,
        issued_at: row.try_get("issued_at")?,
    })
}

async fn frozen_members_for_capability(
    connection: &mut PgConnection,
    row: &PgRow,
    capability: &CalibrationEvidenceReadCapability,
) -> Result<Option<Vec<FrozenMember>>, StoreError> {
    let tenant: &str = row.try_get("tenant_id")?;
    let site: &str = row.try_get("site_id")?;
    let capability_id: &str = row.try_get("capability_id")?;
    let rows = sqlx::query(
        "SELECT role, sample_index, artifact_id, catalog_bytes_saved,
                catalog_integrity_digest, catalog_kind, catalog_content_type,
                catalog_fidelity, catalog_classification, catalog_expires_at,
                catalog_event_id
         FROM xshield.calibration_read_capability_members
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3
         ORDER BY role, sample_index NULLS FIRST, artifact_id
         FOR UPDATE",
    )
    .bind(tenant)
    .bind(site)
    .bind(capability_id)
    .fetch_all(&mut *connection)
    .await?;
    let expected = capability.evidence_refs();
    if rows.len() != expected.len() {
        return Ok(None);
    }
    let mut actual = BTreeMap::new();
    for row in rows {
        let role: String = row.try_get("role")?;
        let sample_index: Option<i32> = row.try_get("sample_index")?;
        let member = FrozenMember {
            role: role_from_storage(&role)?,
            sample_index: sample_index
                .map(|index| {
                    u16::try_from(index)
                        .map_err(|_| StoreError::CorruptData("calibration_member_sample_index"))
                })
                .transpose()?,
            snapshot: CatalogSnapshot {
                artifact_id: row.try_get("artifact_id")?,
                bytes_saved: u64::try_from(row.try_get::<i64, _>("catalog_bytes_saved")?)
                    .map_err(|_| StoreError::CorruptData("catalog_bytes_saved"))?,
                integrity_digest: row.try_get("catalog_integrity_digest")?,
                kind: row.try_get("catalog_kind")?,
                content_type: row.try_get("catalog_content_type")?,
                fidelity: row.try_get("catalog_fidelity")?,
                classification: row.try_get("catalog_classification")?,
                expires_at: row.try_get("catalog_expires_at")?,
                catalog_event_id: row.try_get("catalog_event_id")?,
            },
        };
        if actual.insert((role, sample_index), member).is_some() {
            return Err(StoreError::CorruptData("duplicate_calibration_member"));
        }
    }

    let mut members = Vec::with_capacity(expected.len());
    for reference in expected {
        let key = (
            reference.role().as_str().to_owned(),
            reference.sample_index().map(i32::from),
        );
        let Some(member) = actual.remove(&key) else {
            return Ok(None);
        };
        if member.snapshot.artifact_id != reference.artifact_id().as_str() {
            return Ok(None);
        }
        members.push(member);
    }
    if !actual.is_empty() {
        return Err(StoreError::CorruptData("unexpected_calibration_member"));
    }
    Ok(Some(members))
}

async fn durable_capability_matches(
    connection: &mut PgConnection,
    header: &PgRow,
    capability: &CalibrationEvidenceReadCapability,
) -> Result<bool, StoreError> {
    if !header_matches_capability(header, capability)? {
        return Ok(false);
    }
    let Some(members) = frozen_members_for_capability(connection, header, capability).await? else {
        return Ok(false);
    };
    frozen_scope_matches(header, capability, &members)
}

fn frozen_scope_matches(
    header: &PgRow,
    capability: &CalibrationEvidenceReadCapability,
    members: &[FrozenMember],
) -> Result<bool, StoreError> {
    let member_count = i32::try_from(members.len())
        .map_err(|_| StoreError::NumericRange("frozen_member_count"))?;
    let frozen_total_bytes = members.iter().try_fold(0_u64, |total, member| {
        total
            .checked_add(member.snapshot.bytes_saved)
            .ok_or(StoreError::NumericRange("frozen_total_bytes"))
    })?;
    let persisted_digest: [u8; 32] = header
        .try_get::<Vec<u8>, _>("scope_digest")?
        .try_into()
        .map_err(|_| StoreError::CorruptData("calibration_scope_digest"))?;
    let persisted_total = u64::try_from(header.try_get::<i64, _>("frozen_total_bytes")?)
        .map_err(|_| StoreError::CorruptData("calibration_frozen_total_bytes"))?;
    Ok(header.try_get::<i32, _>("member_count")? == member_count
        && persisted_total == frozen_total_bytes
        && frozen_total_bytes <= capability.max_total_bytes()
        && scope_digest(capability, members) == persisted_digest)
}

fn role_from_storage(value: &str) -> Result<CalibrationEvidenceRole, StoreError> {
    match value {
        "training_manifest" => Ok(CalibrationEvidenceRole::TrainingManifest),
        "calibration_manifest" => Ok(CalibrationEvidenceRole::CalibrationManifest),
        "evaluation_manifest" => Ok(CalibrationEvidenceRole::EvaluationManifest),
        "label_manifest" => Ok(CalibrationEvidenceRole::LabelManifest),
        "model_call_record" => Ok(CalibrationEvidenceRole::ModelCallRecord),
        "reviewed_label" => Ok(CalibrationEvidenceRole::ReviewedLabel),
        _ => Err(StoreError::CorruptData("calibration_member_role")),
    }
}

async fn members_match_live_catalog(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
    header: &PgRow,
) -> Result<bool, StoreError> {
    let rows = sqlx::query(
        "SELECT member.role, member.sample_index, member.artifact_id,
                member.catalog_bytes_saved, member.catalog_integrity_digest,
                member.catalog_kind, member.catalog_content_type, member.catalog_fidelity,
                member.catalog_classification, member.catalog_expires_at, member.catalog_event_id,
                catalog.bytes_saved AS live_bytes_saved,
                catalog.integrity_digest AS live_integrity_digest,
                catalog.kind AS live_kind, catalog.content_type AS live_content_type,
                catalog.fidelity AS live_fidelity, catalog.classification AS live_classification,
                catalog.expires_at AS live_expires_at, catalog.catalog_event_id AS live_event_id,
                catalog.status AS live_status, catalog.deleted_at AS live_deleted_at
         FROM xshield.calibration_read_capability_members member
         JOIN xshield.artifact_catalog catalog
           ON catalog.tenant_id=member.tenant_id AND catalog.site_id=member.site_id
          AND catalog.artifact_id=member.artifact_id
         WHERE member.tenant_id=$1 AND member.site_id=$2 AND member.capability_id=$3
         ORDER BY member.artifact_id
         FOR UPDATE OF member, catalog",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() != capability.evidence_refs().len() {
        return Ok(false);
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *connection)
        .await?;
    let end = unix_timestamp(capability.expires_at())?;
    let mut total = 0_u64;
    for row in rows {
        if row.try_get::<&str, _>("live_status")? != "active"
            || row
                .try_get::<Option<DateTime<Utc>>, _>("live_deleted_at")?
                .is_some()
            || row.try_get::<DateTime<Utc>, _>("live_expires_at")? <= now
            || row.try_get::<DateTime<Utc>, _>("live_expires_at")? < end
            || row.try_get::<i64, _>("live_bytes_saved")?
                != row.try_get::<i64, _>("catalog_bytes_saved")?
            || row.try_get::<&str, _>("live_integrity_digest")?
                != row.try_get::<&str, _>("catalog_integrity_digest")?
            || row.try_get::<&str, _>("live_kind")? != row.try_get::<&str, _>("catalog_kind")?
            || row.try_get::<&str, _>("live_content_type")?
                != row.try_get::<&str, _>("catalog_content_type")?
            || row.try_get::<&str, _>("live_fidelity")?
                != row.try_get::<&str, _>("catalog_fidelity")?
            || row.try_get::<&str, _>("live_classification")?
                != row.try_get::<&str, _>("catalog_classification")?
            || row.try_get::<DateTime<Utc>, _>("live_expires_at")?
                != row.try_get::<DateTime<Utc>, _>("catalog_expires_at")?
            || row.try_get::<&str, _>("live_event_id")?
                != row.try_get::<&str, _>("catalog_event_id")?
        {
            return Ok(false);
        }
        total = total
            .checked_add(
                u64::try_from(row.try_get::<i64, _>("live_bytes_saved")?)
                    .map_err(|_| StoreError::CorruptData("live_catalog_bytes_saved"))?,
            )
            .ok_or(StoreError::NumericRange("live_catalog_total"))?;
    }
    Ok(total
        == u64::try_from(header.try_get::<i64, _>("frozen_total_bytes")?)
            .map_err(|_| StoreError::CorruptData("frozen_total_bytes"))?
        && total <= capability.max_total_bytes())
}

async fn active_lease_matches_request(
    connection: &mut PgConnection,
    header: &PgRow,
    request: &CalibrationEvidenceReadRequest<'_>,
    now: DateTime<Utc>,
) -> Result<Option<PgRow>, StoreError> {
    if header.try_get::<&str, _>("status")? != "leased"
        || now < unix_timestamp(request.capability().not_before())?
        || now >= unix_timestamp(request.capability().expires_at())?
    {
        return Ok(None);
    }
    let lease = sqlx::query(
        "SELECT * FROM xshield.calibration_read_capability_leases
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4
         FOR UPDATE",
    )
    .bind(request.tenant_id().as_str())
    .bind(request.site_id().as_str())
    .bind(request.capability().capability_id().as_str())
    .bind(request.session().lease().lease_id().as_str())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(lease) = lease else {
        return Ok(None);
    };
    let token_digest = sha256(request.session().lease().token());
    if lease.try_get::<&str, _>("status")? != "active"
        || lease
            .try_get::<Vec<u8>, _>("lease_token_digest")?
            .as_slice()
            != token_digest
        || lease.try_get::<DateTime<Utc>, _>("acquired_at")? > now
        || lease.try_get::<DateTime<Utc>, _>("lease_until")? <= now
    {
        return Ok(None);
    }
    Ok(Some(lease))
}

/// Checks the private lease material for a state-changing full-batch completion.
///
/// Unlike a read authorization, this additionally binds the configured runner
/// that acquired the lease. The caller already locks the header and complete
/// catalog scope; this function only answers whether that exact active lease
/// can be moved to `completed` in the same transaction.
async fn active_lease_matches_completion(
    connection: &mut PgConnection,
    header: &PgRow,
    capability: &CalibrationEvidenceReadCapability,
    session: &CalibrationEvidenceReadSession<'_>,
    runner_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    if header.try_get::<&str, _>("status")? != "leased" {
        return Ok(false);
    }
    let lease = sqlx::query(
        "SELECT status, runner_id, lease_token_digest, acquired_at, lease_until
         FROM xshield.calibration_read_capability_leases
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4
         FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(session.lease().lease_id().as_str())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(lease) = lease else {
        return Ok(false);
    };
    let token_digest = sha256(session.lease().token());
    Ok(lease.try_get::<&str, _>("status")? == "active"
        && lease.try_get::<&str, _>("runner_id")? == runner_id
        && lease
            .try_get::<Vec<u8>, _>("lease_token_digest")?
            .as_slice()
            == token_digest
        && lease.try_get::<DateTime<Utc>, _>("acquired_at")? <= now
        && lease.try_get::<DateTime<Utc>, _>("lease_until")? > now)
}

/// Recognizes the exact completed lease after an unknown completion commit.
///
/// This intentionally does not inspect live catalog state or wall-clock
/// expiry: a committed terminal state remains retry-identifiable even when
/// source retention later changes. It cannot authorize a new read or lease.
async fn completed_lease_matches(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
    session: &CalibrationEvidenceReadSession<'_>,
    runner_id: &str,
) -> Result<bool, StoreError> {
    let lease = sqlx::query(
        "SELECT status, runner_id, lease_token_digest
         FROM xshield.calibration_read_capability_leases
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4
         FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(session.lease().lease_id().as_str())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(lease) = lease else {
        return Ok(false);
    };
    let token_digest = sha256(session.lease().token());
    Ok(lease.try_get::<&str, _>("status")? == "completed"
        && lease.try_get::<&str, _>("runner_id")? == runner_id
        && lease
            .try_get::<Vec<u8>, _>("lease_token_digest")?
            .as_slice()
            == token_digest)
}

/// Ensures an unknown-commit retry cannot call a consumed capability complete
/// when its atomic security terminal was manually removed or never committed.
async fn completion_event_exists(
    connection: &mut PgConnection,
    header: &PgRow,
    capability: &CalibrationEvidenceReadCapability,
) -> Result<bool, StoreError> {
    let Some(event_id) = header.try_get::<Option<String>, _>("completion_event_id")? else {
        return Ok(false);
    };
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM xshield.audit_outbox
             WHERE event_id=$1 AND tenant_id=$2 AND site_id=$3
               AND aggregate_ref=$4 AND event_type=$5
         )",
    )
    .bind(event_id)
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(COMPLETED_EVENT_TYPE)
    .fetch_one(&mut *connection)
    .await?)
}

async fn authorized_member_for_request(
    connection: &mut PgConnection,
    request: &CalibrationEvidenceReadRequest<'_>,
    _lease: PgRow,
) -> Result<Option<AuthorizedCalibrationEvidence>, StoreError> {
    let row = sqlx::query(
        "SELECT member.role AS calibration_role,
                member.sample_index AS calibration_sample_index,
                catalog.*
         FROM xshield.calibration_read_capability_members member
         JOIN xshield.artifact_catalog catalog
           ON catalog.tenant_id=member.tenant_id AND catalog.site_id=member.site_id
          AND catalog.artifact_id=member.artifact_id
         WHERE member.tenant_id=$1 AND member.site_id=$2 AND member.capability_id=$3
           AND member.artifact_id=$4
         FOR SHARE OF member, catalog",
    )
    .bind(request.tenant_id().as_str())
    .bind(request.site_id().as_str())
    .bind(request.capability().capability_id().as_str())
    .bind(request.evidence_ref().artifact_id().as_str())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let role = role_from_storage(row.try_get("calibration_role")?)?;
    let sample_index = row
        .try_get::<Option<i32>, _>("calibration_sample_index")?
        .map(|value| {
            u16::try_from(value).map_err(|_| StoreError::CorruptData("calibration_sample_index"))
        })
        .transpose()?;
    if role != request.evidence_ref().role()
        || sample_index != request.evidence_ref().sample_index()
    {
        return Ok(None);
    }
    Ok(Some(AuthorizedCalibrationEvidence {
        artifact: catalog_artifact(&row)?,
        role,
        sample_index,
    }))
}

async fn resolve_live_or_recovery(
    connection: &mut PgConnection,
    header: &PgRow,
    now: DateTime<Utc>,
) -> Result<LeasePreparation, StoreError> {
    let status: &str = header.try_get("status")?;
    let current_generation: i32 = header.try_get("lease_generation")?;
    let recoveries: i32 = header.try_get("recovery_attempts")?;
    if matches!(status, "consumed" | "expired" | "revoked") {
        return Ok(LeasePreparation::Unavailable);
    }
    if status == "issued" {
        return Ok(LeasePreparation::Start);
    }
    if status == "leased" {
        let lease = current_lease(connection, header, current_generation).await?;
        if lease.try_get::<&str, _>("status")? != "active" {
            return Err(StoreError::CorruptData("calibration_active_lease"));
        }
        if lease.try_get::<DateTime<Utc>, _>("lease_until")? > now {
            return Ok(LeasePreparation::Busy);
        }
        let changed = sqlx::query(
            "UPDATE xshield.calibration_read_capability_leases
             SET status='recovery_required', recovery_required_at=$5
             WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3
               AND lease_generation=$4 AND status='active'",
        )
        .bind(header.try_get::<&str, _>("tenant_id")?)
        .bind(header.try_get::<&str, _>("site_id")?)
        .bind(header.try_get::<&str, _>("capability_id")?)
        .bind(current_generation)
        .bind(date_millis(now))
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::CorruptData("calibration_active_lease"));
        }
        let changed = sqlx::query(
            "UPDATE xshield.calibration_read_capabilities
             SET status='recovery_required', recovery_required_at=$4
             WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND status='leased'",
        )
        .bind(header.try_get::<&str, _>("tenant_id")?)
        .bind(header.try_get::<&str, _>("site_id")?)
        .bind(header.try_get::<&str, _>("capability_id")?)
        .bind(date_millis(now))
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::CorruptData("calibration_recovery_header"));
        }
    } else if status != "recovery_required" {
        return Err(StoreError::CorruptData("calibration_capability_status"));
    }
    if recoveries >= MAX_RECOVERIES {
        abandon_latest_lease(connection, header, current_generation, now).await?;
        let changed = sqlx::query(
            "UPDATE xshield.calibration_read_capabilities
             SET status='expired', recovery_required_at=NULL, expired_at=$4
             WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3
               AND status='recovery_required'",
        )
        .bind(header.try_get::<&str, _>("tenant_id")?)
        .bind(header.try_get::<&str, _>("site_id")?)
        .bind(header.try_get::<&str, _>("capability_id")?)
        .bind(date_millis(now))
        .execute(&mut *connection)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::CorruptData("calibration_expiring_header"));
        }
        return Ok(LeasePreparation::RecoveryExhausted);
    }
    abandon_latest_lease(connection, header, current_generation, now).await?;
    Ok(LeasePreparation::Recover {
        generation: current_generation + 1,
    })
}

async fn current_lease(
    connection: &mut PgConnection,
    header: &PgRow,
    generation: i32,
) -> Result<PgRow, StoreError> {
    sqlx::query(
        "SELECT * FROM xshield.calibration_read_capability_leases
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_generation=$4
         FOR UPDATE",
    )
    .bind(header.try_get::<&str, _>("tenant_id")?)
    .bind(header.try_get::<&str, _>("site_id")?)
    .bind(header.try_get::<&str, _>("capability_id")?)
    .bind(generation)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(StoreError::CorruptData("calibration_current_lease"))
}

async fn abandon_latest_lease(
    connection: &mut PgConnection,
    header: &PgRow,
    generation: i32,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let changed = sqlx::query(
        "UPDATE xshield.calibration_read_capability_leases
         SET status='abandoned', recovery_required_at=NULL, abandoned_at=$5
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3
           AND lease_generation=$4 AND status='recovery_required'",
    )
    .bind(header.try_get::<&str, _>("tenant_id")?)
    .bind(header.try_get::<&str, _>("site_id")?)
    .bind(header.try_get::<&str, _>("capability_id")?)
    .bind(generation)
    .bind(date_millis(now))
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(StoreError::CorruptData("calibration_recovery_lease"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_lease(
    connection: &mut PgConnection,
    capability: &CalibrationEvidenceReadCapability,
    runner_id: &str,
    lease_id: &CalibrationReadLeaseId,
    generation: i32,
    token_digest: &[u8; 32],
    acquired_at: DateTime<Utc>,
    lease_until: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO xshield.calibration_read_capability_leases (
             tenant_id, site_id, capability_id, lease_id, lease_generation, runner_id,
             lease_token_digest, status, acquired_at, lease_until
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$9)",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(lease_id.as_str())
    .bind(generation)
    .bind(runner_id)
    .bind(token_digest.as_slice())
    .bind(date_millis(acquired_at))
    .bind(date_millis(lease_until))
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn expire_capability_if_needed(
    connection: &mut PgConnection,
    header: &PgRow,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let status: &str = header.try_get("status")?;
    let generation: i32 = header.try_get("lease_generation")?;
    match status {
        "leased" => {
            let changed = sqlx::query(
                "UPDATE xshield.calibration_read_capability_leases
                 SET status='abandoned', abandoned_at=$5
                 WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3
                   AND lease_generation=$4 AND status='active'",
            )
            .bind(header.try_get::<&str, _>("tenant_id")?)
            .bind(header.try_get::<&str, _>("site_id")?)
            .bind(header.try_get::<&str, _>("capability_id")?)
            .bind(generation)
            .bind(date_millis(now))
            .execute(&mut *connection)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(StoreError::CorruptData("calibration_expiring_lease"));
            }
        }
        "recovery_required" => {
            abandon_latest_lease(connection, header, generation, now).await?;
        }
        "issued" => {}
        "consumed" | "expired" | "revoked" => return Ok(()),
        _ => return Err(StoreError::CorruptData("calibration_capability_status")),
    }
    let changed = sqlx::query(
        "UPDATE xshield.calibration_read_capabilities
         SET status='expired', recovery_required_at=NULL, expired_at=$4
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3
           AND status=$5",
    )
    .bind(header.try_get::<&str, _>("tenant_id")?)
    .bind(header.try_get::<&str, _>("site_id")?)
    .bind(header.try_get::<&str, _>("capability_id")?)
    .bind(date_millis(now))
    .bind(status)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if changed != 1 {
        return Err(StoreError::CorruptData("calibration_expiring_header"));
    }
    Ok(())
}

fn unix_timestamp(value: UnixSeconds) -> Result<DateTime<Utc>, StoreError> {
    let seconds =
        i64::try_from(value.value()).map_err(|_| StoreError::NumericRange("unix_seconds"))?;
    DateTime::from_timestamp(seconds, 0).ok_or(StoreError::InvalidCommand)
}

fn unix_seconds(value: DateTime<Utc>, field: &'static str) -> Result<UnixSeconds, StoreError> {
    if value.timestamp_subsec_nanos() != 0 || value.timestamp() < 0 {
        return Err(StoreError::CorruptData(field));
    }
    Ok(UnixSeconds::new(
        u64::try_from(value.timestamp()).map_err(|_| StoreError::CorruptData(field))?,
    ))
}

fn date_millis(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond(value.timestamp_subsec_millis() * 1_000_000)
        .unwrap_or(value)
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
