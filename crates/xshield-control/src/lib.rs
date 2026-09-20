//! Authenticated control-plane HTTP endpoints and their mandatory access audit.
//!
//! The control plane uses an independently provisioned management credential,
//! server-derived tenant/site scope, and a separate encrypted audit producer.

#![warn(missing_docs)]

mod case_close;
mod case_collection;
mod case_holds;
mod case_items;
mod case_list;
mod evidence_access_inspection;
mod evidence_access_list;
mod ledger_inspection;
mod search;

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, Path, RawQuery, State,
        rejection::{JsonRejection, PathRejection},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{SecondsFormat, Utc};
use clickhouse::Client;
use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sha::sha256, sign::Signer};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;
use xshield_audit::{JournalError, JournalKey, JournalRecord, LocalJournal, SealVerifyingKey};
use xshield_core::{
    admin::{ManagementPrincipal, ManagementRole},
    domain::{
        ArtifactId, AuthBindingId, CaseId, EventId, EvidenceAccessRequestId, GrantId, ModelCallId,
        RequestId, SiteId, TenantId,
    },
    investigation::{
        EvidenceAccessDecisionDraft, EvidenceAccessKind, EvidenceAccessRequestDraft,
        InvestigationCaseDraft,
    },
};
use xshield_evidence::{EvidenceError, EvidenceManifest, LocalEvidenceVault};
use xshield_postgres::{
    EvidenceAccessCapability, EvidenceAccessDecisionCreate, EvidenceAccessDecisionRecord,
    EvidenceAccessDecisionWriteOutcome, EvidenceAccessRequestCreate, EvidenceAccessRequestRecord,
    EvidenceAccessRequestWriteOutcome, EvidenceCatalogArtifactQuery, EvidenceCatalogPage,
    EvidenceCatalogQuery, InvestigationCaseCreate, InvestigationCaseRecord,
    InvestigationCaseWriteOutcome, PostgresIdentityStore,
};
use xshield_worker::{
    IndexWatermark, ModelCallSummary, PublicationHealth, PublishError, PublisherConfig,
    RequestEventPosition, RequestEvents, RequestSummary, inspect_publication_health,
    query_model_call, query_request_events, query_request_summary,
};
use zeroize::Zeroizing;

const HEALTH_PATH: &str = "/control/v1/audit/health";
const REQUEST_SUMMARY_PATH: &str = "/control/v1/requests/{request_id}";
const REQUEST_EVENTS_PATH: &str = "/control/v1/requests/{request_id}/events";
const REQUEST_EVIDENCE_PATH: &str = "/control/v1/requests/{request_id}/evidence";
const MODEL_CALL_PATH: &str = "/control/v1/model-calls/{model_call_id}";
const ARTIFACT_PATH: &str = "/control/v1/artifacts/{artifact_id}";
const EVIDENCE_ACCESS_PATH: &str = "/control/v1/artifacts/{artifact_id}/access";
const EVIDENCE_ACCESS_APPROVE_PATH: &str =
    "/control/v1/evidence-access-requests/{access_request_id}/approve";
const EVIDENCE_ACCESS_DENY_PATH: &str =
    "/control/v1/evidence-access-requests/{access_request_id}/deny";
const EVIDENCE_CONTENT_PATH: &str = "/control/v1/artifacts/{artifact_id}/content";
const EVIDENCE_ACCESS_REQUEST_HEADER: &str = "x-xshield-evidence-access-request";
const CASES_PATH: &str = "/control/v1/cases";
const RATE_WINDOW: Duration = Duration::from_mins(1);
const TOKEN_BYTES_MAX: usize = 512;
const TOKEN_LIFETIME_MAX_SECONDS: u64 = 24 * 60 * 60;
const MAX_QUERY_EVENTS: u16 = 1_000;
const MAX_QUERY_ARTIFACTS: u16 = 128;
const MAX_OPEN_CASES: u32 = 10_000;
const MAX_PENDING_EVIDENCE_ACCESS_REQUESTS: u32 = 10_000;
const MAX_EVIDENCE_ACCESS_TTL_SECONDS: u32 = 24 * 60 * 60;
const CASE_BODY_BYTES_MAX: usize = 4 * 1024;
const CURSOR_BYTES_MAX: usize = 160;
const CURSOR_VERSION: &str = "v1";

#[derive(Clone, Copy)]
struct AccessAction {
    event_type: &'static str,
    method: &'static str,
    path: &'static str,
    role: ManagementRole,
}

const HEALTH_ACCESS: AccessAction = AccessAction {
    event_type: "console.health.read",
    method: "GET",
    path: HEALTH_PATH,
    role: ManagementRole::AuditAdministrator,
};
const REQUEST_EVENTS_ACCESS: AccessAction = AccessAction {
    event_type: "console.events.read",
    method: "GET",
    path: REQUEST_EVENTS_PATH,
    role: ManagementRole::Observer,
};
const REQUEST_SUMMARY_ACCESS: AccessAction = AccessAction {
    event_type: "console.request.read",
    method: "GET",
    path: REQUEST_SUMMARY_PATH,
    role: ManagementRole::Observer,
};
const REQUEST_EVIDENCE_ACCESS: AccessAction = AccessAction {
    event_type: "console.manifest.read",
    method: "GET",
    path: REQUEST_EVIDENCE_PATH,
    role: ManagementRole::Observer,
};
const MODEL_CALL_ACCESS: AccessAction = AccessAction {
    event_type: "console.model.read",
    method: "GET",
    path: MODEL_CALL_PATH,
    role: ManagementRole::Observer,
};
const ARTIFACT_ACCESS: AccessAction = AccessAction {
    event_type: "console.manifest.read",
    method: "GET",
    path: ARTIFACT_PATH,
    role: ManagementRole::Observer,
};
const CASE_CREATE_ACCESS: AccessAction = AccessAction {
    event_type: "case.created",
    method: "POST",
    path: CASES_PATH,
    role: ManagementRole::Investigator,
};
const EVIDENCE_ACCESS_REQUEST: AccessAction = AccessAction {
    event_type: "evidence.access.requested",
    method: "POST",
    path: EVIDENCE_ACCESS_PATH,
    role: ManagementRole::Investigator,
};
const EVIDENCE_ACCESS_APPROVE: AccessAction = AccessAction {
    event_type: "evidence.access.approved",
    method: "POST",
    path: EVIDENCE_ACCESS_APPROVE_PATH,
    role: ManagementRole::SensitiveEvidenceApprover,
};
const EVIDENCE_ACCESS_DENY: AccessAction = AccessAction {
    event_type: "evidence.access.denied",
    method: "POST",
    path: EVIDENCE_ACCESS_DENY_PATH,
    role: ManagementRole::SensitiveEvidenceApprover,
};
const EVIDENCE_CONTENT_ACCESS: AccessAction = AccessAction {
    event_type: "evidence.read",
    method: "GET",
    path: EVIDENCE_CONTENT_PATH,
    role: ManagementRole::SensitiveEvidenceReader,
};

/// Time-bounded management bearer material reduced to a one-way digest.
pub struct ManagementCredential {
    token_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
}

/// Dedicated HMAC key for scope-bound event pagination cursors.
pub struct CursorKey(Zeroizing<[u8; 32]>);

impl CursorKey {
    /// Parses one 32-byte lowercase hexadecimal cursor key.
    ///
    /// # Errors
    /// Returns [`ControlError::InvalidConfig`] for malformed key material.
    pub fn from_hex(value: &str) -> Result<Self, ControlError> {
        parse_lower_hex_32(value)
            .map(Zeroizing::new)
            .map(Self)
            .ok_or(ControlError::InvalidConfig)
    }
}

/// Dedicated HMAC key for management mutation idempotency.
pub struct IdempotencyKey(Zeroizing<[u8; 32]>);

impl IdempotencyKey {
    /// Parses one 32-byte lowercase hexadecimal idempotency key.
    ///
    /// # Errors
    /// Returns [`ControlError::InvalidConfig`] for malformed key material.
    pub fn from_hex(value: &str) -> Result<Self, ControlError> {
        parse_lower_hex_32(value)
            .map(Zeroizing::new)
            .map(Self)
            .ok_or(ControlError::InvalidConfig)
    }
}

/// Vault-backed port that consumes an already validated evidence capability.
pub struct EvidenceReadPort {
    vault: LocalEvidenceVault,
    capacity: Arc<Semaphore>,
}

impl EvidenceReadPort {
    /// Opens the content boundary with one whole-object read in flight.
    ///
    /// The reservation covers decryption, audit, and all response-buffer clones.
    /// Saturated reads receive an audited retryable error before vault I/O.
    #[must_use]
    pub fn new(vault: LocalEvidenceVault) -> Self {
        Self {
            vault,
            // ponytail: one retained object per port; use a weighted byte budget
            // when measured download throughput requires parallel reads.
            capacity: Arc::new(Semaphore::new(1)),
        }
    }

    fn read_content(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        capability: &EvidenceAccessCapability,
        permit: OwnedSemaphorePermit,
    ) -> Result<EvidenceContent, EvidenceError> {
        let manifest = self.vault.read_manifest(
            tenant_id,
            site_id,
            capability.artifact().artifact_id().as_str(),
        )?;
        if manifest.manifest() != capability.artifact().manifest() {
            return Err(EvidenceError::CorruptEvidence);
        }
        let bytes = self.vault.read_content(
            tenant_id,
            site_id,
            capability.artifact().artifact_id().as_str(),
        )?;
        Ok(EvidenceContent {
            bytes,
            _permit: permit,
        })
    }
}

// Keep admission and plaintext together even after HTTP yields a body frame.
// Bytes::from_owner retains this owner until its last buffer clone is dropped.
struct EvidenceContent {
    bytes: Zeroizing<Vec<u8>>,
    _permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for EvidenceContent {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Validated request-rate and query-result ceilings for one control process.
#[derive(Clone, Copy)]
pub struct ControlLimits {
    requests_per_minute: u64,
    max_query_events: u16,
    max_query_artifacts: u16,
    max_open_cases: u32,
    max_pending_evidence_access_requests: u32,
    max_evidence_access_ttl_seconds: u32,
}

impl ControlLimits {
    /// Validates non-zero management budgets and hard query ceilings.
    ///
    /// # Errors
    /// Returns [`ControlError::InvalidConfig`] when a limit is outside its bound.
    pub fn new(
        requests_per_minute: u64,
        max_query_events: u16,
        max_query_artifacts: u16,
        max_open_cases: u32,
        max_pending_evidence_access_requests: u32,
        max_evidence_access_ttl_seconds: u32,
    ) -> Result<Self, ControlError> {
        if requests_per_minute == 0
            || !(1..=MAX_QUERY_EVENTS).contains(&max_query_events)
            || !(1..=MAX_QUERY_ARTIFACTS).contains(&max_query_artifacts)
            || !(1..=MAX_OPEN_CASES).contains(&max_open_cases)
            || !(1..=MAX_PENDING_EVIDENCE_ACCESS_REQUESTS)
                .contains(&max_pending_evidence_access_requests)
            || !(1..=MAX_EVIDENCE_ACCESS_TTL_SECONDS).contains(&max_evidence_access_ttl_seconds)
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(Self {
            requests_per_minute,
            max_query_events,
            max_query_artifacts,
            max_open_cases,
            max_pending_evidence_access_requests,
            max_evidence_access_ttl_seconds,
        })
    }
}

impl ManagementCredential {
    /// Validates a bearer and a non-empty lifetime of at most 24 hours.
    ///
    /// # Errors
    /// Returns [`ControlError::InvalidConfig`] for weak material or invalid bounds.
    pub fn new(bearer_token: &str, issued_at: u64, expires_at: u64) -> Result<Self, ControlError> {
        let lifetime = expires_at.checked_sub(issued_at);
        if bearer_token.len() < 32
            || bearer_token.len() > TOKEN_BYTES_MAX
            || bearer_token.chars().any(char::is_control)
            || issued_at == 0
            || !lifetime.is_some_and(|value| value > 0 && value <= TOKEN_LIFETIME_MAX_SECONDS)
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(Self {
            token_digest: sha256(bearer_token.as_bytes()),
            issued_at,
            expires_at,
        })
    }
}

/// Validated dependencies and security policy for the health endpoint.
pub struct ControlConfig {
    credential: ManagementCredential,
    cursor_key: CursorKey,
    idempotency_key: IdempotencyKey,
    principal: ManagementPrincipal,
    tenant_id: TenantId,
    site_id: SiteId,
    publisher: PublisherConfig,
    source_journal_key_id: String,
    limits: ControlLimits,
}

impl ControlConfig {
    /// Builds a single-scope control configuration from trusted startup input.
    ///
    /// The bearer token is reduced to a digest immediately. Tenant and site are
    /// server-derived and are not accepted from the HTTP request.
    ///
    /// # Errors
    /// Returns [`ControlError::InvalidConfig`] for a weak or malformed scalar.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential: ManagementCredential,
        cursor_key: CursorKey,
        idempotency_key: IdempotencyKey,
        principal: ManagementPrincipal,
        tenant_id: TenantId,
        site_id: SiteId,
        publisher: PublisherConfig,
        source_journal_key_id: impl Into<String>,
        limits: ControlLimits,
    ) -> Result<Self, ControlError> {
        let source_journal_key_id = source_journal_key_id.into();
        if !distinct_control_keys(&cursor_key, &idempotency_key)
            || source_journal_key_id.is_empty()
            || source_journal_key_id.len() > 128
            || source_journal_key_id.chars().any(char::is_control)
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(Self {
            credential,
            cursor_key,
            idempotency_key,
            principal,
            tenant_id,
            site_id,
            publisher,
            source_journal_key_id,
            limits,
        })
    }
}

fn distinct_control_keys(cursor_key: &CursorKey, idempotency_key: &IdempotencyKey) -> bool {
    !memcmp::eq(&cursor_key.0[..], &idempotency_key.0[..])
}

/// Runtime state for the authenticated audit-health endpoint.
pub struct ControlPlane {
    config: ControlConfig,
    source_journal_key: JournalKey,
    seal_key: SealVerifyingKey,
    index: Client,
    search_capacity: Arc<Semaphore>,
    case_evidence_capacity: Arc<Semaphore>,
    catalog: PostgresIdentityStore,
    evidence_read: Option<Arc<EvidenceReadPort>>,
    access_journal: Mutex<LocalJournal>,
    unauthenticated_rate: Mutex<RateWindow>,
    rate: Mutex<RateWindow>,
}

impl ControlPlane {
    /// Creates a control plane around already-opened, dedicated access journal.
    #[must_use]
    pub fn new(
        config: ControlConfig,
        source_journal_key: JournalKey,
        seal_key: SealVerifyingKey,
        index: Client,
        catalog: PostgresIdentityStore,
        access_journal: LocalJournal,
    ) -> Self {
        let rate_limit = config.limits.requests_per_minute;
        Self {
            unauthenticated_rate: Mutex::new(RateWindow::new(rate_limit)),
            rate: Mutex::new(RateWindow::new(rate_limit)),
            config,
            source_journal_key,
            seal_key,
            index,
            // ponytail: one analytical query per control instance; share a
            // tenant budget across replicas when measured load requires it.
            search_capacity: Arc::new(Semaphore::new(1)),
            case_evidence_capacity: Arc::new(Semaphore::new(1)),
            catalog,
            evidence_read: None,
            access_journal: Mutex::new(access_journal),
        }
    }

    /// Installs the vault-backed content port at the trusted composition root.
    #[must_use]
    pub fn with_evidence_read_port(mut self, port: EvidenceReadPort) -> Self {
        self.evidence_read = Some(Arc::new(port));
        self
    }

    fn health(&self, authorization: Option<&str>) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let subject = match self.authorize(authorization, &request_id, HEALTH_ACCESS) {
            Ok(subject) => subject,
            Err(response) => return *response,
        };

        let Ok(health) = inspect_publication_health(
            &self.config.publisher,
            &self.config.source_journal_key_id,
            &self.source_journal_key,
            &self.seal_key,
        ) else {
            return self.audited_error(
                &request_id,
                Some(&subject),
                HEALTH_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_HEALTH_UNAVAILABLE",
                "audit health is temporarily unavailable",
                true,
                "retry_later",
            );
        };
        if self
            .append_access_event(
                &request_id,
                Some(&subject),
                HEALTH_ACCESS,
                None,
                "PASS",
                "CONTROL_HEALTH_READ",
            )
            .is_err()
        {
            return audit_unavailable(&request_id);
        }
        EndpointResult::Success(HealthResponse {
            request_id,
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            health,
        })
    }

    async fn request_events(
        self: Arc<Self>,
        authorization: Option<String>,
        target_request_id: String,
        raw_query: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request_id,
                REQUEST_EVENTS_ACCESS,
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Ok(target_request_id) = RequestId::parse(target_request_id) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_EVENTS_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_REQUEST_ID_INVALID",
                    "invalid request identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let after = match parse_cursor_query(raw_query.as_deref()).and_then(|cursor| {
            cursor
                .map(|cursor| self.decode_cursor(&subject, &target_request_id, cursor))
                .transpose()
        }) {
            Ok(after) => after,
            Err(CursorError::Invalid) => {
                return self
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        REQUEST_EVENTS_ACCESS,
                        Some(target_request_id),
                        StatusCode::BAD_REQUEST,
                        "CONTROL_CURSOR_INVALID",
                        "invalid pagination cursor",
                        false,
                        "restart_query",
                    )
                    .await;
            }
            Err(CursorError::Unavailable) => {
                return self
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        REQUEST_EVENTS_ACCESS,
                        Some(target_request_id),
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_CURSOR_UNAVAILABLE",
                        "pagination service is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await;
            }
        };
        let Ok(events) = query_request_events(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            &target_request_id,
            after.as_ref(),
            self.config.limits.max_query_events,
        )
        .await
        else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_EVENTS_ACCESS,
                    Some(target_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_INDEX_UNAVAILABLE",
                    "audit index is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        self.complete_request_events(request_id, subject, target_request_id, events)
            .await
    }

    async fn request_evidence(
        self: Arc<Self>,
        authorization: Option<String>,
        target_request_id: String,
        raw_query: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request_id,
                REQUEST_EVIDENCE_ACCESS,
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Ok(target_request_id) = RequestId::parse(target_request_id) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_EVIDENCE_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_REQUEST_ID_INVALID",
                    "invalid request identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let after = match parse_cursor_query(raw_query.as_deref()).and_then(|cursor| {
            cursor
                .map(|cursor| self.decode_evidence_cursor(&subject, &target_request_id, cursor))
                .transpose()
        }) {
            Ok(after) => after,
            Err(CursorError::Invalid) => {
                return self
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        REQUEST_EVIDENCE_ACCESS,
                        Some(target_request_id),
                        StatusCode::BAD_REQUEST,
                        "CONTROL_CURSOR_INVALID",
                        "invalid pagination cursor",
                        false,
                        "restart_query",
                    )
                    .await;
            }
            Err(CursorError::Unavailable) => {
                return self
                    .audited_error_async(
                        request_id,
                        Some(subject),
                        REQUEST_EVIDENCE_ACCESS,
                        Some(target_request_id),
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_CURSOR_UNAVAILABLE",
                        "pagination service is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await;
            }
        };
        let query = EvidenceCatalogQuery::new(
            &self.config.tenant_id,
            &self.config.site_id,
            &target_request_id,
            after.as_ref(),
            self.config.limits.max_query_artifacts,
        );
        let Ok(query) = query else {
            return internal_error(&request_id);
        };
        let Ok(page) = self.catalog.list_request_artifacts(query).await else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_EVIDENCE_ACCESS,
                    Some(target_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_CATALOG_UNAVAILABLE",
                    "evidence catalog is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        self.complete_request_evidence(request_id, subject, target_request_id, page)
            .await
    }

    async fn model_call(
        self: Arc<Self>,
        authorization: Option<String>,
        target_model_call_id: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request_id,
                MODEL_CALL_ACCESS,
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Some(target_model_call_id) =
            target_model_call_id.and_then(|id| ModelCallId::parse(id).ok())
        else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    MODEL_CALL_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_MODEL_CALL_ID_INVALID",
                    "invalid model call identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(permit) = Arc::clone(&self.search_capacity).try_acquire_owned() else {
            return self
                .finish_model_call(
                    request_id,
                    subject,
                    target_model_call_id,
                    Err(search::SearchFailure::Capacity),
                )
                .await;
        };
        let task_request_id = request_id.clone();
        // Like search, an admitted lookup retains its permit through terminal
        // audit even if its HTTP client disconnects.
        match tokio::spawn(async move {
            let _permit = permit;
            let result = self.run_model_call(&target_model_call_id).await;
            self.finish_model_call(task_request_id, subject, target_model_call_id, result)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn run_model_call(
        self: &Arc<Self>,
        target: &ModelCallId,
    ) -> Result<(Option<ModelCallSummary>, PublicationHealth), search::SearchFailure> {
        // This health describes only the configured journal, not every producer
        // contributing to the index. It cannot prove a missing call never existed.
        let control = Arc::clone(self);
        let health = tokio::task::spawn_blocking(move || {
            inspect_publication_health(
                &control.config.publisher,
                &control.config.source_journal_key_id,
                &control.source_journal_key,
                &control.seal_key,
            )
        })
        .await
        .map_err(|_| search::SearchFailure::HealthUnavailable)?
        .map_err(|_| search::SearchFailure::HealthUnavailable)?;
        let model_call = query_model_call(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            target,
        )
        .await
        .map_err(|error| match error {
            PublishError::QueryBudgetExceeded => search::SearchFailure::Budget,
            PublishError::QueryTimeout => search::SearchFailure::Timeout,
            _ => search::SearchFailure::IndexUnavailable,
        })?;
        Ok((model_call, health))
    }

    async fn finish_model_call(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target_model_call_id: ModelCallId,
        result: Result<(Option<ModelCallSummary>, PublicationHealth), search::SearchFailure>,
    ) -> EndpointResult {
        let evidence_refs = result
            .as_ref()
            .ok()
            .and_then(|(summary, _)| summary.as_ref())
            .map(model_call_evidence_refs)
            .unwrap_or_default();
        let reason = result
            .as_ref()
            .map_or_else(search::SearchFailure::reason, |_| "CONTROL_MODEL_CALL_READ");
        let outcome = match &result {
            Ok(_) => "PASS",
            Err(search::SearchFailure::Capacity | search::SearchFailure::Budget) => "DENY",
            Err(_) => "ERROR",
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_model_call_id = target_model_call_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let refs = evidence_refs.iter().map(String::as_str).collect::<Vec<_>>();
            audit_control.append_model_access_event(
                &audit_request_id,
                Some(&audit_subject),
                &audit_model_call_id,
                outcome,
                reason,
                &refs,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        let (model_call, health) = match result {
            Ok(result) => result,
            Err(search::SearchFailure::Budget) => {
                return api_error(
                    &request_id,
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_QUERY_BUDGET_EXCEEDED",
                    "model call lookup exceeded its query budget",
                    false,
                    "contact_operator",
                );
            }
            Err(error) => return error.response(request_id),
        };
        let completeness = match model_call.as_ref() {
            Some(summary) if summary.lifecycle_complete => "complete",
            Some(summary) if matches!(summary.status.as_str(), "started" | "requested") => {
                "pending"
            }
            Some(_) => "partial",
            None => "not_indexed",
        };
        EndpointResult::ModelCall(ModelCallResponse {
            request_id,
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            source_model_call_id: target_model_call_id.as_str().to_owned(),
            watermark_scope: "configured_journal",
            as_of: health.as_of,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            pending_segments: health.pending_segments,
            found: model_call.is_some(),
            completeness,
            model_call,
        })
    }

    async fn complete_request_evidence(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target_request_id: RequestId,
        page: EvidenceCatalogPage,
    ) -> EndpointResult {
        let next_cursor = match page.next_artifact_id() {
            Some(artifact_id) => {
                match self.encode_evidence_cursor(&subject, &target_request_id, artifact_id) {
                    Ok(cursor) => Some(cursor),
                    Err(()) => {
                        return self
                            .audited_error_async(
                                request_id,
                                Some(subject),
                                REQUEST_EVIDENCE_ACCESS,
                                Some(target_request_id),
                                StatusCode::SERVICE_UNAVAILABLE,
                                "CONTROL_CURSOR_UNAVAILABLE",
                                "pagination service is temporarily unavailable",
                                true,
                                "retry_later",
                            )
                            .await;
                    }
                }
            }
            None => None,
        };
        let artifact_refs = page
            .artifacts()
            .iter()
            .map(|artifact| artifact.artifact_id().as_str().to_owned())
            .collect::<Vec<_>>();
        let artifacts = page
            .artifacts()
            .iter()
            .map(|artifact| EvidenceArtifactResponse {
                recorded_at: artifact
                    .recorded_at()
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
                manifest: artifact.manifest().clone(),
            })
            .collect();
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_target = target_request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let evidence_refs = artifact_refs.iter().map(String::as_str).collect::<Vec<_>>();
            audit_control.append_access_event_with_evidence(
                &audit_request_id,
                Some(&audit_subject),
                REQUEST_EVIDENCE_ACCESS,
                Some(&audit_target),
                None,
                None,
                None,
                "PASS",
                "CONTROL_MANIFESTS_READ",
                &evidence_refs,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::RequestEvidence(RequestEvidenceResponse {
            request_id,
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            source_request_id: target_request_id.as_str().to_owned(),
            truncated: next_cursor.is_some(),
            next_cursor,
            artifacts,
        })
    }

    async fn artifact(
        self: Arc<Self>,
        authorization: Option<String>,
        target_artifact_id: String,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request_id, ARTIFACT_ACCESS)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Ok(target_artifact_id) = ArtifactId::parse(target_artifact_id) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    ARTIFACT_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_ARTIFACT_ID_INVALID",
                    "invalid artifact identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let artifact = self
            .catalog
            .find_artifact(EvidenceCatalogArtifactQuery::new(
                &self.config.tenant_id,
                &self.config.site_id,
                &target_artifact_id,
            ))
            .await;
        let Ok(artifact) = artifact else {
            return self
                .audited_artifact_error_async(
                    request_id,
                    subject,
                    target_artifact_id,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_CATALOG_UNAVAILABLE",
                    "evidence catalog is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let found = artifact.is_some();
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_artifact_id = target_artifact_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            let evidence_refs = found
                .then_some(audit_artifact_id.as_str())
                .into_iter()
                .collect::<Vec<_>>();
            audit_control.append_access_event_with_evidence(
                &audit_request_id,
                Some(&audit_subject),
                ARTIFACT_ACCESS,
                None,
                Some(&audit_artifact_id),
                None,
                None,
                "PASS",
                "CONTROL_MANIFEST_READ",
                &evidence_refs,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::Artifact(ArtifactResponse {
            request_id,
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            source_artifact_id: target_artifact_id.as_str().to_owned(),
            found,
            artifact: artifact.as_ref().map(evidence_artifact_response),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn create_case(
        self: Arc<Self>,
        authorization: Option<String>,
        idempotency_key: Option<String>,
        payload: Option<CreateCaseRequest>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request_id,
                CASE_CREATE_ACCESS,
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Some(idempotency_key) = idempotency_key.filter(|value| valid_idempotency_key(value))
        else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_IDEMPOTENCY_KEY_INVALID",
                    "a valid idempotency key is required",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(payload) = payload else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CASE_REQUEST_INVALID",
                    "invalid case request",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(case_id) = CaseId::parse(format!("case_{}", Uuid::now_v7())) else {
            return internal_error(&request_id);
        };
        let Ok(draft) = InvestigationCaseDraft::new(
            case_id,
            self.config.tenant_id.clone(),
            self.config.site_id.clone(),
            subject.clone(),
            payload.purpose,
        ) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CASE_REQUEST_INVALID",
                    "invalid case request",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some((idempotency_digest, request_digest)) = self.case_digests(
            &subject,
            idempotency_key.as_bytes(),
            draft.purpose().as_bytes(),
        ) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_IDEMPOTENCY_UNAVAILABLE",
                    "case creation is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_CASE_BUSY",
                    "case operation is already in progress",
                    true,
                    "retry_later",
                )
                .await;
        };
        let task_request = request_id.clone();
        // Keep admission through the database result and mandatory audit even
        // if the browser disconnects after a commit. Exact retries recover it.
        match tokio::spawn(async move {
            let _permit = permit;
            self.persist_case(
                task_request,
                subject,
                draft,
                idempotency_digest,
                request_digest,
            )
            .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn persist_case(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        draft: InvestigationCaseDraft,
        idempotency_digest: [u8; 32],
        request_digest: [u8; 32],
    ) -> EndpointResult {
        let Ok(typed_request_id) = RequestId::parse(request_id.clone()) else {
            return internal_error(&request_id);
        };
        let Ok(event_id) = EventId::parse(format!("ev_{}", Uuid::now_v7())) else {
            return internal_error(&request_id);
        };
        let envelope = case_created_envelope(&event_id, &typed_request_id, &draft, &request_digest);
        let command = InvestigationCaseCreate::new(
            &draft,
            &idempotency_digest,
            &request_digest,
            &typed_request_id,
            &event_id,
            &envelope,
            self.config.limits.max_open_cases,
        );
        let Ok(command) = command else {
            return internal_error(&request_id);
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.create_investigation_case(command),
        )
        .await;
        let Ok(Ok(outcome)) = outcome else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_CASE_STORE_UNAVAILABLE",
                    "case store is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        match outcome {
            InvestigationCaseWriteOutcome::Created(case) => {
                self.complete_case(request_id, subject, case, StatusCode::CREATED, false)
                    .await
            }
            InvestigationCaseWriteOutcome::Existing(case) => {
                self.complete_case(request_id, subject, case, StatusCode::OK, true)
                    .await
            }
            InvestigationCaseWriteOutcome::Conflict => {
                self.audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::CONFLICT,
                    "CONTROL_IDEMPOTENCY_CONFLICT",
                    "idempotency key is already bound to another request",
                    false,
                    "use_original_request",
                )
                .await
            }
            InvestigationCaseWriteOutcome::CapacityExceeded => {
                self.audited_error_async(
                    request_id,
                    Some(subject),
                    CASE_CREATE_ACCESS,
                    None,
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_CASE_CAPACITY_EXCEEDED",
                    "open case capacity is exhausted",
                    true,
                    "close_or_reuse_case",
                )
                .await
            }
        }
    }

    async fn complete_case(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        case: InvestigationCaseRecord,
        status: StatusCode,
        replayed: bool,
    ) -> EndpointResult {
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_case_id = case.case_id().clone();
        let reason_code = if replayed {
            "CONTROL_CASE_ALREADY_CREATED"
        } else {
            "CONTROL_CASE_CREATED"
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event_with_evidence(
                &audit_request_id,
                Some(&audit_subject),
                CASE_CREATE_ACCESS,
                None,
                None,
                Some(&audit_case_id),
                None,
                "PASS",
                reason_code,
                &[],
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::Case(
            status,
            CreateCaseResponse {
                request_id,
                tenant_id: self.config.tenant_id.as_str().to_owned(),
                site_id: self.config.site_id.as_str().to_owned(),
                case_id: case.case_id().as_str().to_owned(),
                status: case.status(),
                purpose: case.purpose().to_owned(),
                created_at: case
                    .created_at()
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
                replayed,
            },
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn request_evidence_access(
        self: Arc<Self>,
        authorization: Option<String>,
        idempotency_key: Option<String>,
        target_artifact_id: String,
        payload: Option<CreateEvidenceAccessRequest>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request_id,
                EVIDENCE_ACCESS_REQUEST,
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Some(idempotency_key) = idempotency_key.filter(|value| valid_idempotency_key(value))
        else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    None,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_IDEMPOTENCY_KEY_INVALID",
                    "a valid idempotency key is required",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(artifact_id) = ArtifactId::parse(target_artifact_id) else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    None,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_ARTIFACT_ID_INVALID",
                    "invalid artifact identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(payload) = payload else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ACCESS_REQUEST_INVALID",
                    "invalid evidence access request",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(case_id) = CaseId::parse(payload.case_id) else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_CASE_ID_INVALID",
                    "invalid case identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(access_request_id) =
            EvidenceAccessRequestId::parse(format!("access_{}", Uuid::now_v7()))
        else {
            return internal_error(&request_id);
        };
        let Ok(draft) = EvidenceAccessRequestDraft::new(
            access_request_id,
            self.config.tenant_id.clone(),
            self.config.site_id.clone(),
            case_id.clone(),
            artifact_id.clone(),
            subject.clone(),
            payload.access_kind.into(),
            payload.justification,
        ) else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(case_id),
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ACCESS_REQUEST_INVALID",
                    "invalid evidence access request",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some((idempotency_digest, request_digest)) =
            self.evidence_access_digests(&subject, idempotency_key.as_bytes(), &draft)
        else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(case_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_IDEMPOTENCY_UNAVAILABLE",
                    "evidence access request is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(case_id),
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_EVIDENCE_ACCESS_BUSY",
                    "evidence access operation is already in progress",
                    true,
                    "retry_later",
                )
                .await;
        };
        let task_request = request_id.clone();
        // Admission outlives HTTP cancellation so committed attempts still reach
        // their mandatory audit. An uncertain response is recovered by exact retry.
        match tokio::spawn(async move {
            let _permit = permit;
            self.persist_evidence_access_request(
                task_request,
                subject,
                draft,
                idempotency_digest,
                request_digest,
            )
            .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn persist_evidence_access_request(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        draft: EvidenceAccessRequestDraft,
        idempotency_digest: [u8; 32],
        request_digest: [u8; 32],
    ) -> EndpointResult {
        let artifact_id = draft.artifact_id().clone();
        let case_id = draft.case_id().clone();
        let Ok(typed_request_id) = RequestId::parse(request_id.clone()) else {
            return internal_error(&request_id);
        };
        let Ok(event_id) = EventId::parse(format!("ev_{}", Uuid::now_v7())) else {
            return internal_error(&request_id);
        };
        let envelope = evidence_access_requested_envelope(
            &event_id,
            &typed_request_id,
            &draft,
            &request_digest,
        );
        let Ok(command) = EvidenceAccessRequestCreate::new(
            &draft,
            &idempotency_digest,
            &request_digest,
            &typed_request_id,
            &event_id,
            &envelope,
            self.config.limits.max_pending_evidence_access_requests,
        ) else {
            return internal_error(&request_id);
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.create_evidence_access_request(command),
        )
        .await;
        let Ok(Ok(outcome)) = outcome else {
            return self
                .audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(case_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EVIDENCE_ACCESS_STORE_UNAVAILABLE",
                    "evidence access store is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        match outcome {
            EvidenceAccessRequestWriteOutcome::Created(record) => {
                self.complete_evidence_access_request(
                    request_id,
                    subject,
                    draft,
                    record,
                    StatusCode::CREATED,
                    false,
                )
                .await
            }
            EvidenceAccessRequestWriteOutcome::Existing(record) => {
                self.complete_evidence_access_request(
                    request_id,
                    subject,
                    draft,
                    record,
                    StatusCode::OK,
                    true,
                )
                .await
            }
            EvidenceAccessRequestWriteOutcome::Conflict => {
                self.audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(case_id),
                    StatusCode::CONFLICT,
                    "CONTROL_IDEMPOTENCY_CONFLICT",
                    "idempotency key is already bound to another request",
                    false,
                    "use_original_request",
                )
                .await
            }
            EvidenceAccessRequestWriteOutcome::TargetUnavailable => {
                self.audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(case_id),
                    StatusCode::NOT_FOUND,
                    "CONTROL_EVIDENCE_ACCESS_TARGET_UNAVAILABLE",
                    "case or evidence is unavailable",
                    false,
                    "verify_scope",
                )
                .await
            }
            EvidenceAccessRequestWriteOutcome::CapacityExceeded => {
                self.audited_evidence_access_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(case_id),
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_EVIDENCE_ACCESS_CAPACITY_EXCEEDED",
                    "pending evidence access capacity is exhausted",
                    true,
                    "resolve_pending_requests",
                )
                .await
            }
        }
    }

    async fn complete_evidence_access_request(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        draft: EvidenceAccessRequestDraft,
        record: EvidenceAccessRequestRecord,
        status: StatusCode,
        replayed: bool,
    ) -> EndpointResult {
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_artifact_id = draft.artifact_id().clone();
        let audit_case_id = draft.case_id().clone();
        let audit_access_request_id = record.access_request_id().clone();
        let reason_code = if replayed {
            "CONTROL_EVIDENCE_ACCESS_ALREADY_REQUESTED"
        } else {
            "CONTROL_EVIDENCE_ACCESS_REQUESTED"
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event_with_evidence(
                &audit_request_id,
                Some(&audit_subject),
                EVIDENCE_ACCESS_REQUEST,
                None,
                Some(&audit_artifact_id),
                Some(&audit_case_id),
                Some(&audit_access_request_id),
                "PASS",
                reason_code,
                &[audit_artifact_id.as_str()],
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::EvidenceAccessRequest(
            status,
            EvidenceAccessRequestResponse {
                request_id,
                tenant_id: self.config.tenant_id.as_str().to_owned(),
                site_id: self.config.site_id.as_str().to_owned(),
                access_request_id: record.access_request_id().as_str().to_owned(),
                case_id: draft.case_id().as_str().to_owned(),
                artifact_id: draft.artifact_id().as_str().to_owned(),
                access_kind: draft.kind().as_str(),
                status: record.status(),
                requested_at: record
                    .requested_at()
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
                replayed,
            },
        )
    }

    #[allow(clippy::too_many_lines)]
    async fn read_evidence_content(
        self: Arc<Self>,
        authorization: Option<String>,
        target_artifact_id: String,
        access_request_id: Option<String>,
        query_present: bool,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request_id,
                EVIDENCE_CONTENT_ACCESS,
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Ok(artifact_id) = ArtifactId::parse(target_artifact_id) else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    None,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ARTIFACT_ID_INVALID",
                    "invalid evidence artifact identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(access_request_id) = access_request_id else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ACCESS_REQUEST_REQUIRED",
                    "an approved evidence access request is required",
                    false,
                    "provide_access_request",
                )
                .await;
        };
        if query_present {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_READ_REQUEST_INVALID",
                    "invalid evidence content request",
                    false,
                    "correct_request",
                )
                .await;
        }
        let Ok(access_request_id) = EvidenceAccessRequestId::parse(access_request_id) else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ACCESS_REQUEST_ID_INVALID",
                    "invalid evidence access request identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(access_request_id),
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_EVIDENCE_ACCESS_BUSY",
                    "evidence access operation is already in progress",
                    true,
                    "retry_later",
                )
                .await;
        };
        let task_request = request_id.clone();
        // Once admitted, authorization and any decrypted content reach a durable
        // read audit even after disconnect. The vault permit separately follows
        // the plaintext through its response-body lifetime.
        match tokio::spawn(async move {
            let _permit = permit;
            self.complete_evidence_content(task_request, subject, artifact_id, access_request_id)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn complete_evidence_content(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        artifact_id: ArtifactId,
        access_request_id: EvidenceAccessRequestId,
    ) -> EndpointResult {
        let capability = match tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.find_evidence_access_capability(
                &self.config.tenant_id,
                &self.config.site_id,
                &access_request_id,
                &artifact_id,
                &subject,
            ),
        )
        .await
        {
            Ok(Ok(Some(capability))) => capability,
            Ok(Ok(None)) => {
                return self
                    .audited_evidence_read_error_async(
                        request_id,
                        subject,
                        Some(artifact_id),
                        Some(access_request_id),
                        StatusCode::NOT_FOUND,
                        "CONTROL_EVIDENCE_READ_NOT_AVAILABLE",
                        "evidence content is unavailable",
                        false,
                        "verify_access",
                    )
                    .await;
            }
            Ok(Err(_)) | Err(_) => {
                return self
                    .audited_evidence_read_error_async(
                        request_id,
                        subject,
                        Some(artifact_id),
                        Some(access_request_id),
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_EVIDENCE_READ_STORE_UNAVAILABLE",
                        "evidence access is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await;
            }
        };
        let Some(port) = self.evidence_read.clone() else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(access_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EVIDENCE_READ_UNAVAILABLE",
                    "evidence content is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let tenant_id = self.config.tenant_id.clone();
        let site_id = self.config.site_id.clone();
        let read_capability = capability.clone();
        let Ok(permit) = Arc::clone(&port.capacity).try_acquire_owned() else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(access_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EVIDENCE_READ_CAPACITY_EXHAUSTED",
                    "evidence read capacity is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        // Move admission into the blocking task: cancelling its async caller
        // must not admit another object while decryption is still running.
        let content = match tokio::task::spawn_blocking(move || {
            port.read_content(&tenant_id, &site_id, &read_capability, permit)
        })
        .await
        {
            Ok(Ok(content)) => content,
            Ok(Err(EvidenceError::NotAvailable)) => {
                return self
                    .audited_evidence_read_error_async(
                        request_id,
                        subject,
                        Some(artifact_id),
                        Some(access_request_id),
                        StatusCode::NOT_FOUND,
                        "CONTROL_EVIDENCE_READ_NOT_AVAILABLE",
                        "evidence content is unavailable",
                        false,
                        "verify_access",
                    )
                    .await;
            }
            Ok(Err(_)) | Err(_) => {
                return self
                    .audited_evidence_read_error_async(
                        request_id,
                        subject,
                        Some(artifact_id),
                        Some(access_request_id),
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CONTROL_EVIDENCE_READ_CORRUPT",
                        "evidence content is temporarily unavailable",
                        true,
                        "retry_later",
                    )
                    .await;
            }
        };
        let Ok(bytes_read) = u64::try_from(content.as_ref().len()) else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(access_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EVIDENCE_READ_TOO_LARGE",
                    "evidence content is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_artifact_id = artifact_id.clone();
        let audit_access_request_id = access_request_id.clone();
        // Binary responses carry the same authenticated scope and exact targets
        // as JSON envelopes, so browsers can reject stale or mismatched bytes
        // before creating a downloadable object. All values originate from
        // validated identifiers or the bounded plaintext length.
        let byte_length = bytes_read.to_string();
        let metadata = [
            ("x-xshield-request-id", request_id.as_str()),
            ("x-xshield-tenant-id", self.config.tenant_id.as_str()),
            ("x-xshield-site-id", self.config.site_id.as_str()),
            ("x-xshield-artifact-id", artifact_id.as_str()),
            (EVIDENCE_ACCESS_REQUEST_HEADER, access_request_id.as_str()),
            ("content-length", byte_length.as_str()),
        ]
        .into_iter()
        .map(|(name, value)| HeaderValue::from_str(value).map(|value| (name, value)))
        .collect::<Result<Vec<_>, _>>();
        let Ok(metadata) = metadata else {
            return self
                .audited_evidence_read_error_async(
                    request_id,
                    subject,
                    Some(artifact_id),
                    Some(access_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EVIDENCE_READ_CORRUPT",
                    "evidence content is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event_with_evidence_bytes(
                &audit_request_id,
                Some(&audit_subject),
                EVIDENCE_CONTENT_ACCESS,
                None,
                Some(&audit_artifact_id),
                None,
                Some(&audit_access_request_id),
                None,
                "PASS",
                "CONTROL_EVIDENCE_READ",
                &[audit_artifact_id.as_str()],
                Some(bytes_read),
                None,
                None,
                None,
                None,
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        let mut response = Response::new(Body::from(Bytes::from_owner(content)));
        *response.status_mut() = StatusCode::OK;
        let headers = response.headers_mut();
        for (name, value) in metadata {
            headers.insert(name, value);
        }
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"evidence.bin\""),
        );
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        EndpointResult::Raw(no_store(response))
    }

    #[allow(clippy::too_many_lines)]
    async fn decide_evidence_access(
        self: Arc<Self>,
        action: AccessAction,
        authorization: Option<String>,
        idempotency_key: Option<String>,
        target_access_request_id: String,
        input: Option<EvidenceAccessDecisionInput>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(authorization.as_deref(), &auth_request_id, action)
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Some(idempotency_key) = idempotency_key.filter(|value| valid_idempotency_key(value))
        else {
            return self
                .audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_IDEMPOTENCY_KEY_INVALID",
                    "a valid idempotency key is required",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(access_request_id) = EvidenceAccessRequestId::parse(target_access_request_id) else {
            return self
                .audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ACCESS_REQUEST_ID_INVALID",
                    "invalid evidence access request identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some(input) = input else {
            return self
                .audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ACCESS_DECISION_INVALID",
                    "invalid evidence access decision",
                    false,
                    "correct_request",
                )
                .await;
        };
        let decision = match input {
            EvidenceAccessDecisionInput::Approve(payload) => EvidenceAccessDecisionDraft::approve(
                self.config.tenant_id.clone(),
                self.config.site_id.clone(),
                access_request_id.clone(),
                subject.clone(),
                payload.reason,
                payload.ttl_seconds,
                self.config.limits.max_evidence_access_ttl_seconds,
            ),
            EvidenceAccessDecisionInput::Deny(payload) => EvidenceAccessDecisionDraft::deny(
                self.config.tenant_id.clone(),
                self.config.site_id.clone(),
                access_request_id.clone(),
                subject.clone(),
                payload.reason,
            ),
        };
        let Ok(decision) = decision else {
            return self
                .audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::BAD_REQUEST,
                    "CONTROL_EVIDENCE_ACCESS_DECISION_INVALID",
                    "invalid evidence access decision",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Some((idempotency_digest, request_digest)) =
            self.evidence_access_decision_digests(&subject, idempotency_key.as_bytes(), &decision)
        else {
            return self
                .audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_IDEMPOTENCY_UNAVAILABLE",
                    "evidence access decision is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let Ok(permit) = Arc::clone(&self.case_evidence_capacity).try_acquire_owned() else {
            return self
                .audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_EVIDENCE_ACCESS_BUSY",
                    "evidence access operation is already in progress",
                    true,
                    "retry_later",
                )
                .await;
        };
        let task_request = request_id.clone();
        // Decision commit and its access audit finish under the same admission,
        // even when the caller stops waiting for the result.
        match tokio::spawn(async move {
            let _permit = permit;
            self.persist_evidence_access_decision(
                task_request,
                subject,
                action,
                decision,
                idempotency_digest,
                request_digest,
            )
            .await
        })
        .await
        {
            Ok(result) => result,
            Err(_) => internal_error(&request_id),
        }
    }

    async fn persist_evidence_access_decision(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        action: AccessAction,
        decision: EvidenceAccessDecisionDraft,
        idempotency_digest: [u8; 32],
        request_digest: [u8; 32],
    ) -> EndpointResult {
        let access_request_id = decision.access_request_id().clone();
        let Ok(typed_request_id) = RequestId::parse(request_id.clone()) else {
            return internal_error(&request_id);
        };
        let Ok(event_id) = EventId::parse(format!("ev_{}", Uuid::now_v7())) else {
            return internal_error(&request_id);
        };
        let envelope = evidence_access_decision_envelope(
            &event_id,
            &typed_request_id,
            &decision,
            &request_digest,
        );
        let Ok(command) = EvidenceAccessDecisionCreate::new(
            &decision,
            &idempotency_digest,
            &request_digest,
            &typed_request_id,
            &event_id,
            &envelope,
        ) else {
            return internal_error(&request_id);
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            self.catalog.decide_evidence_access(command),
        )
        .await;
        let Ok(Ok(outcome)) = outcome else {
            return self
                .audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_EVIDENCE_ACCESS_DECISION_STORE_UNAVAILABLE",
                    "evidence access decision store is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        match outcome {
            EvidenceAccessDecisionWriteOutcome::Created(record) => {
                self.complete_evidence_access_decision(request_id, subject, action, record, false)
                    .await
            }
            EvidenceAccessDecisionWriteOutcome::Existing(record) => {
                self.complete_evidence_access_decision(request_id, subject, action, record, true)
                    .await
            }
            EvidenceAccessDecisionWriteOutcome::Conflict => {
                self.audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::CONFLICT,
                    "CONTROL_EVIDENCE_ACCESS_DECISION_CONFLICT",
                    "evidence access request already has another decision",
                    false,
                    "use_original_decision",
                )
                .await
            }
            EvidenceAccessDecisionWriteOutcome::TargetUnavailable => {
                self.audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::NOT_FOUND,
                    "CONTROL_EVIDENCE_ACCESS_DECISION_TARGET_UNAVAILABLE",
                    "evidence access request is unavailable",
                    false,
                    "verify_scope",
                )
                .await
            }
            EvidenceAccessDecisionWriteOutcome::SelfApprovalDenied => {
                self.audited_evidence_decision_error_async(
                    request_id,
                    subject,
                    action,
                    Some(access_request_id),
                    StatusCode::FORBIDDEN,
                    "CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED",
                    "independent approval is required",
                    false,
                    "use_independent_approver",
                )
                .await
            }
        }
    }

    async fn complete_evidence_access_decision(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        action: AccessAction,
        record: EvidenceAccessDecisionRecord,
        replayed: bool,
    ) -> EndpointResult {
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_artifact_id = record.artifact_id().clone();
        let audit_case_id = record.case_id().clone();
        let audit_access_request_id = record.access_request_id().clone();
        let reason_code = match (record.status(), replayed) {
            ("approved", false) => "CONTROL_EVIDENCE_ACCESS_APPROVED",
            ("denied", false) => "CONTROL_EVIDENCE_ACCESS_DENIED",
            _ => "CONTROL_EVIDENCE_ACCESS_DECISION_REPLAYED",
        };
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event_with_evidence(
                &audit_request_id,
                Some(&audit_subject),
                action,
                None,
                Some(&audit_artifact_id),
                Some(&audit_case_id),
                Some(&audit_access_request_id),
                "PASS",
                reason_code,
                &[audit_artifact_id.as_str()],
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::EvidenceAccessDecision(EvidenceAccessDecisionResponse {
            request_id,
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            access_request_id: record.access_request_id().as_str().to_owned(),
            case_id: record.case_id().as_str().to_owned(),
            artifact_id: record.artifact_id().as_str().to_owned(),
            requested_by: record.requested_by().to_owned(),
            decided_by: record.decided_by().to_owned(),
            status: record.status(),
            decided_at: record
                .decided_at()
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            access_expires_at: record
                .access_expires_at()
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
            replayed,
        })
    }

    fn evidence_access_decision_digests(
        &self,
        subject: &str,
        idempotency_key: &[u8],
        decision: &EvidenceAccessDecisionDraft,
    ) -> Option<([u8; 32], [u8; 32])> {
        let common = [
            subject.as_bytes(),
            self.config.tenant_id.as_str().as_bytes(),
            self.config.site_id.as_str().as_bytes(),
        ];
        let idempotency_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-evidence-access-decision-idempotency-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
            ],
        )
        .ok()?;
        let ttl = decision
            .requested_ttl_seconds()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let request_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-evidence-access-decision-request-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
                decision.access_request_id().as_str().as_bytes(),
                decision.kind().as_str().as_bytes(),
                decision.reason().as_bytes(),
                ttl.as_bytes(),
            ],
        )
        .ok()?;
        Some((idempotency_digest, request_digest))
    }

    fn evidence_access_digests(
        &self,
        subject: &str,
        idempotency_key: &[u8],
        draft: &EvidenceAccessRequestDraft,
    ) -> Option<([u8; 32], [u8; 32])> {
        let common = [
            subject.as_bytes(),
            self.config.tenant_id.as_str().as_bytes(),
            self.config.site_id.as_str().as_bytes(),
        ];
        let idempotency_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-evidence-access-idempotency-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
            ],
        )
        .ok()?;
        let request_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-evidence-access-request-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
                draft.case_id().as_str().as_bytes(),
                draft.artifact_id().as_str().as_bytes(),
                draft.kind().as_str().as_bytes(),
                draft.justification().as_bytes(),
            ],
        )
        .ok()?;
        Some((idempotency_digest, request_digest))
    }

    fn case_digests(
        &self,
        subject: &str,
        idempotency_key: &[u8],
        purpose: &[u8],
    ) -> Option<([u8; 32], [u8; 32])> {
        let common = [
            subject.as_bytes(),
            self.config.tenant_id.as_str().as_bytes(),
            self.config.site_id.as_str().as_bytes(),
        ];
        let idempotency_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-case-idempotency-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
            ],
        )
        .ok()?;
        let request_digest = component_signature(
            &self.config.idempotency_key.0,
            &[
                b"xshield-control-case-request-v1",
                common[0],
                common[1],
                common[2],
                idempotency_key,
                purpose,
            ],
        )
        .ok()?;
        Some((idempotency_digest, request_digest))
    }

    async fn request_summary(
        self: Arc<Self>,
        authorization: Option<String>,
        target_request_id: String,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let auth_control = Arc::clone(&self);
        let auth_request_id = request_id.clone();
        let subject = match tokio::task::spawn_blocking(move || {
            auth_control.authorize(
                authorization.as_deref(),
                &auth_request_id,
                REQUEST_SUMMARY_ACCESS,
            )
        })
        .await
        {
            Ok(Ok(subject)) => subject,
            Ok(Err(response)) => return *response,
            Err(_) => return internal_error(&request_id),
        };
        let Ok(target_request_id) = RequestId::parse(target_request_id) else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_SUMMARY_ACCESS,
                    None,
                    StatusCode::BAD_REQUEST,
                    "CONTROL_REQUEST_ID_INVALID",
                    "invalid request identifier",
                    false,
                    "correct_request",
                )
                .await;
        };
        let Ok(summary) = query_request_summary(
            &self.config.publisher,
            &self.index,
            &self.config.tenant_id,
            &self.config.site_id,
            &target_request_id,
        )
        .await
        else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_SUMMARY_ACCESS,
                    Some(target_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_INDEX_UNAVAILABLE",
                    "audit index is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        self.complete_request_summary(request_id, subject, target_request_id, summary)
            .await
    }

    async fn complete_request_summary(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target_request_id: RequestId,
        summary: Option<RequestSummary>,
    ) -> EndpointResult {
        let health_control = Arc::clone(&self);
        let Ok(Ok(health)) = tokio::task::spawn_blocking(move || {
            inspect_publication_health(
                &health_control.config.publisher,
                &health_control.config.source_journal_key_id,
                &health_control.source_journal_key,
                &health_control.seal_key,
            )
        })
        .await
        else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_SUMMARY_ACCESS,
                    Some(target_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_HEALTH_UNAVAILABLE",
                    "audit health is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let completeness = match summary.as_ref() {
            Some(value) if value.terminal => "complete",
            Some(_) => "pending",
            None if health.pending_segments > 0 || health.has_gaps => "pending_index",
            None => "not_found",
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_target = target_request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event(
                &audit_request_id,
                Some(&audit_subject),
                REQUEST_SUMMARY_ACCESS,
                Some(&audit_target),
                "PASS",
                "CONTROL_REQUEST_READ",
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::RequestSummary(RequestSummaryResponse {
            request_id,
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            source_request_id: target_request_id.as_str().to_owned(),
            as_of: health.as_of,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            pending_segments: health.pending_segments,
            found: summary.is_some(),
            completeness,
            summary,
        })
    }

    async fn complete_request_events(
        self: Arc<Self>,
        request_id: String,
        subject: String,
        target_request_id: RequestId,
        events: RequestEvents,
    ) -> EndpointResult {
        let health_control = Arc::clone(&self);
        let Ok(Ok(health)) = tokio::task::spawn_blocking(move || {
            inspect_publication_health(
                &health_control.config.publisher,
                &health_control.config.source_journal_key_id,
                &health_control.source_journal_key,
                &health_control.seal_key,
            )
        })
        .await
        else {
            return self
                .audited_error_async(
                    request_id,
                    Some(subject),
                    REQUEST_EVENTS_ACCESS,
                    Some(target_request_id),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_HEALTH_UNAVAILABLE",
                    "audit health is temporarily unavailable",
                    true,
                    "retry_later",
                )
                .await;
        };
        let next_cursor = match events.next_position.as_ref() {
            Some(position) => match self.encode_cursor(&subject, &target_request_id, position) {
                Ok(cursor) => Some(cursor),
                Err(()) => {
                    return self
                        .audited_error_async(
                            request_id,
                            Some(subject),
                            REQUEST_EVENTS_ACCESS,
                            Some(target_request_id),
                            StatusCode::SERVICE_UNAVAILABLE,
                            "CONTROL_CURSOR_UNAVAILABLE",
                            "pagination service is temporarily unavailable",
                            true,
                            "retry_later",
                        )
                        .await;
                }
            },
            None => None,
        };
        let audit_control = Arc::clone(&self);
        let audit_request_id = request_id.clone();
        let audit_subject = subject.clone();
        let audit_target = target_request_id.clone();
        let audited = tokio::task::spawn_blocking(move || {
            audit_control.append_access_event(
                &audit_request_id,
                Some(&audit_subject),
                REQUEST_EVENTS_ACCESS,
                Some(&audit_target),
                "PASS",
                "CONTROL_EVENTS_READ",
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            return audit_unavailable(&request_id);
        }
        EndpointResult::RequestEvents(RequestEventsResponse {
            request_id,
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            source_request_id: target_request_id.as_str().to_owned(),
            as_of: health.as_of,
            index_watermark: health.index_watermark,
            has_gaps: health.has_gaps,
            next_cursor,
            events,
        })
    }

    fn encode_cursor(
        &self,
        subject: &str,
        request_id: &RequestId,
        position: &RequestEventPosition,
    ) -> Result<String, ()> {
        let signature = cursor_signature(
            &self.config.cursor_key.0,
            &self.config.credential.token_digest,
            subject,
            &self.config.tenant_id,
            &self.config.site_id,
            request_id,
            self.config.limits.max_query_events,
            position,
        )?;
        Ok(format!(
            "{CURSOR_VERSION}.{}.{}.{}",
            position.request_seq(),
            position.event_id().as_str(),
            lower_hex(&signature)
        ))
    }

    fn decode_cursor(
        &self,
        subject: &str,
        request_id: &RequestId,
        cursor: &str,
    ) -> Result<RequestEventPosition, CursorError> {
        let mut parts = cursor.split('.');
        let (Some(version), Some(sequence), Some(event_id), Some(signature)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if parts.next().is_some() || version != CURSOR_VERSION {
            return Err(CursorError::Invalid);
        }
        let request_seq = sequence
            .parse::<u32>()
            .ok()
            .filter(|value| value.to_string() == sequence)
            .ok_or(CursorError::Invalid)?;
        let event_id = EventId::parse(event_id).map_err(|_| CursorError::Invalid)?;
        let supplied_signature = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let position =
            RequestEventPosition::new(request_seq, event_id).map_err(|_| CursorError::Invalid)?;
        let expected_signature = cursor_signature(
            &self.config.cursor_key.0,
            &self.config.credential.token_digest,
            subject,
            &self.config.tenant_id,
            &self.config.site_id,
            request_id,
            self.config.limits.max_query_events,
            &position,
        )
        .map_err(|()| CursorError::Unavailable)?;
        if !memcmp::eq(&supplied_signature, &expected_signature) {
            return Err(CursorError::Invalid);
        }
        Ok(position)
    }

    fn encode_evidence_cursor(
        &self,
        subject: &str,
        request_id: &RequestId,
        artifact_id: &ArtifactId,
    ) -> Result<String, ()> {
        let signature = evidence_cursor_signature(
            &self.config.cursor_key.0,
            &self.config.credential.token_digest,
            subject,
            &self.config.tenant_id,
            &self.config.site_id,
            request_id,
            self.config.limits.max_query_artifacts,
            artifact_id,
        )?;
        Ok(format!(
            "{CURSOR_VERSION}.{}.{}",
            artifact_id.as_str(),
            lower_hex(&signature)
        ))
    }

    fn decode_evidence_cursor(
        &self,
        subject: &str,
        request_id: &RequestId,
        cursor: &str,
    ) -> Result<ArtifactId, CursorError> {
        let mut parts = cursor.split('.');
        let (Some(version), Some(artifact_id), Some(signature)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if parts.next().is_some() || version != CURSOR_VERSION {
            return Err(CursorError::Invalid);
        }
        let artifact_id = ArtifactId::parse(artifact_id).map_err(|_| CursorError::Invalid)?;
        let supplied_signature = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected_signature = evidence_cursor_signature(
            &self.config.cursor_key.0,
            &self.config.credential.token_digest,
            subject,
            &self.config.tenant_id,
            &self.config.site_id,
            request_id,
            self.config.limits.max_query_artifacts,
            &artifact_id,
        )
        .map_err(|()| CursorError::Unavailable)?;
        if !memcmp::eq(&supplied_signature, &expected_signature) {
            return Err(CursorError::Invalid);
        }
        Ok(artifact_id)
    }

    #[allow(clippy::too_many_arguments)]
    async fn audited_error_async(
        self: &Arc<Self>,
        request_id: String,
        subject: Option<String>,
        action: AccessAction,
        target_request_id: Option<RequestId>,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        let control = Arc::clone(self);
        let fallback_request_id = request_id.clone();
        match tokio::task::spawn_blocking(move || {
            control.audited_error(
                &request_id,
                subject.as_deref(),
                action,
                target_request_id.as_ref(),
                status,
                reason_code,
                message_safe,
                retryable,
                next_action,
            )
        })
        .await
        {
            Ok(response) => response,
            Err(_) => internal_error(&fallback_request_id),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn audited_artifact_error_async(
        self: &Arc<Self>,
        request_id: String,
        subject: String,
        target_artifact_id: ArtifactId,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        let control = Arc::clone(self);
        let fallback_request_id = request_id.clone();
        match tokio::task::spawn_blocking(move || {
            if control
                .append_access_event_with_evidence(
                    &request_id,
                    Some(&subject),
                    ARTIFACT_ACCESS,
                    None,
                    Some(&target_artifact_id),
                    None,
                    None,
                    "DENY",
                    reason_code,
                    &[],
                )
                .is_err()
            {
                return audit_unavailable(&request_id);
            }
            api_error(
                &request_id,
                status,
                reason_code,
                message_safe,
                retryable,
                next_action,
            )
        })
        .await
        {
            Ok(response) => response,
            Err(_) => internal_error(&fallback_request_id),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn audited_evidence_access_error_async(
        self: &Arc<Self>,
        request_id: String,
        subject: String,
        target_artifact_id: Option<ArtifactId>,
        target_case_id: Option<CaseId>,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        let control = Arc::clone(self);
        let fallback_request_id = request_id.clone();
        match tokio::task::spawn_blocking(move || {
            if control
                .append_access_event_with_evidence(
                    &request_id,
                    Some(&subject),
                    EVIDENCE_ACCESS_REQUEST,
                    None,
                    target_artifact_id.as_ref(),
                    target_case_id.as_ref(),
                    None,
                    if status.is_server_error() {
                        "ERROR"
                    } else {
                        "DENY"
                    },
                    reason_code,
                    &[],
                )
                .is_err()
            {
                return audit_unavailable(&request_id);
            }
            api_error(
                &request_id,
                status,
                reason_code,
                message_safe,
                retryable,
                next_action,
            )
        })
        .await
        {
            Ok(response) => response,
            Err(_) => internal_error(&fallback_request_id),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn audited_evidence_decision_error_async(
        self: &Arc<Self>,
        request_id: String,
        subject: String,
        action: AccessAction,
        target_access_request_id: Option<EvidenceAccessRequestId>,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        let control = Arc::clone(self);
        let fallback_request_id = request_id.clone();
        match tokio::task::spawn_blocking(move || {
            if control
                .append_access_event_with_evidence(
                    &request_id,
                    Some(&subject),
                    action,
                    None,
                    None,
                    None,
                    target_access_request_id.as_ref(),
                    if status.is_server_error() {
                        "ERROR"
                    } else {
                        "DENY"
                    },
                    reason_code,
                    &[],
                )
                .is_err()
            {
                return audit_unavailable(&request_id);
            }
            api_error(
                &request_id,
                status,
                reason_code,
                message_safe,
                retryable,
                next_action,
            )
        })
        .await
        {
            Ok(response) => response,
            Err(_) => internal_error(&fallback_request_id),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn audited_evidence_read_error_async(
        self: &Arc<Self>,
        request_id: String,
        subject: String,
        target_artifact_id: Option<ArtifactId>,
        target_access_request_id: Option<EvidenceAccessRequestId>,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        let control = Arc::clone(self);
        let fallback_request_id = request_id.clone();
        match tokio::task::spawn_blocking(move || {
            if control
                .append_access_event_with_evidence(
                    &request_id,
                    Some(&subject),
                    EVIDENCE_CONTENT_ACCESS,
                    None,
                    target_artifact_id.as_ref(),
                    None,
                    target_access_request_id.as_ref(),
                    if status.is_server_error() {
                        "ERROR"
                    } else {
                        "DENY"
                    },
                    reason_code,
                    &[],
                )
                .is_err()
            {
                return audit_unavailable(&request_id);
            }
            api_error(
                &request_id,
                status,
                reason_code,
                message_safe,
                retryable,
                next_action,
            )
        })
        .await
        {
            Ok(response) => response,
            Err(_) => internal_error(&fallback_request_id),
        }
    }

    fn authorize(
        &self,
        authorization: Option<&str>,
        request_id: &str,
        action: AccessAction,
    ) -> Result<String, Box<EndpointResult>> {
        let subject = self.authenticated_subject(authorization, request_id, action)?;
        let Ok(mut rate) = self.rate.lock() else {
            return Err(Box::new(self.audited_error(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_RATE_UNAVAILABLE",
                "management service unavailable",
                true,
                "retry_later",
            )));
        };
        let within_budget = rate.take(Instant::now());
        drop(rate);
        if !within_budget {
            return Err(Box::new(self.audited_error(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::TOO_MANY_REQUESTS,
                "CONTROL_RATE_LIMITED",
                "management request rate exceeded",
                true,
                "retry_later",
            )));
        }
        Ok(subject.to_owned())
    }

    fn authenticated_subject<'a>(
        &'a self,
        authorization: Option<&str>,
        request_id: &str,
        action: AccessAction,
    ) -> Result<&'a str, Box<EndpointResult>> {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return Err(Box::new(self.audited_error(
                request_id,
                None,
                action,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_CLOCK_UNAVAILABLE",
                "management service unavailable",
                true,
                "retry_later",
            )));
        };
        let token_active = now.as_secs() >= self.config.credential.issued_at
            && now.as_secs() < self.config.credential.expires_at;
        let authenticated = token_active
            && authorization
                .and_then(|value| value.strip_prefix("Bearer "))
                .filter(|value| value.len() <= TOKEN_BYTES_MAX)
                .is_some_and(|value| {
                    memcmp::eq(
                        &sha256(value.as_bytes()),
                        &self.config.credential.token_digest,
                    )
                });
        if !authenticated {
            let within_budget = self
                .unauthenticated_rate
                .lock()
                .is_ok_and(|mut rate| rate.take(Instant::now()));
            if !within_budget {
                return Err(Box::new(api_error(
                    request_id,
                    StatusCode::TOO_MANY_REQUESTS,
                    "CONTROL_RATE_LIMITED",
                    "management request rate exceeded",
                    true,
                    "retry_later",
                )));
            }
            return Err(Box::new(self.audited_error(
                request_id,
                None,
                action,
                None,
                StatusCode::UNAUTHORIZED,
                "CONTROL_AUTH_REQUIRED",
                "management authentication required",
                false,
                "authenticate",
            )));
        }

        let subject = self.config.principal.subject();
        if !self.config.principal.authorizes(
            action.role,
            &self.config.tenant_id,
            &self.config.site_id,
        ) {
            return Err(Box::new(self.audited_error(
                request_id,
                Some(subject),
                action,
                None,
                StatusCode::FORBIDDEN,
                "CONTROL_SCOPE_DENIED",
                "management operation forbidden",
                false,
                "request_scope",
            )));
        }
        Ok(subject)
    }

    #[allow(clippy::too_many_arguments)]
    fn audited_error(
        &self,
        request_id: &str,
        subject: Option<&str>,
        action: AccessAction,
        target_request_id: Option<&RequestId>,
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        if self
            .append_access_event(
                request_id,
                subject,
                action,
                target_request_id,
                if status.is_server_error() {
                    "ERROR"
                } else {
                    "DENY"
                },
                reason_code,
            )
            .is_err()
        {
            return audit_unavailable(request_id);
        }
        EndpointResult::Error(
            status,
            ErrorResponse {
                error_code: reason_code,
                message_safe,
                request_id: request_id.to_owned(),
                retryable,
                next_action,
            },
        )
    }

    fn append_access_event(
        &self,
        request_id: &str,
        subject_ref: Option<&str>,
        action: AccessAction,
        target_request_id: Option<&RequestId>,
        outcome: &'static str,
        reason_code: &'static str,
    ) -> Result<(), ControlError> {
        self.append_access_event_with_evidence(
            request_id,
            subject_ref,
            action,
            target_request_id,
            None,
            None,
            None,
            outcome,
            reason_code,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_query_event(
        &self,
        request_id: &str,
        subject_ref: Option<&str>,
        action: AccessAction,
        target_request_id: Option<&RequestId>,
        outcome: &'static str,
        reason_code: &'static str,
        query_digest: &[u8; 32],
    ) -> Result<(), ControlError> {
        let query_digest = lower_hex(query_digest);
        self.append_access_event_with_evidence_bytes(
            request_id,
            subject_ref,
            action,
            target_request_id,
            None,
            None,
            None,
            None,
            outcome,
            reason_code,
            &[],
            None,
            Some(&query_digest),
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_access_event_with_evidence(
        &self,
        request_id: &str,
        subject_ref: Option<&str>,
        action: AccessAction,
        target_request_id: Option<&RequestId>,
        target_artifact_id: Option<&ArtifactId>,
        target_case_id: Option<&CaseId>,
        target_access_request_id: Option<&EvidenceAccessRequestId>,
        outcome: &'static str,
        reason_code: &'static str,
        evidence_refs: &[&str],
    ) -> Result<(), ControlError> {
        self.append_access_event_with_evidence_bytes(
            request_id,
            subject_ref,
            action,
            target_request_id,
            target_artifact_id,
            target_case_id,
            target_access_request_id,
            None,
            outcome,
            reason_code,
            evidence_refs,
            None,
            None,
            None,
            None,
            None,
        )
    }

    fn append_model_access_event(
        &self,
        request_id: &str,
        subject_ref: Option<&str>,
        target_model_call_id: &ModelCallId,
        outcome: &'static str,
        reason_code: &'static str,
        evidence_refs: &[&str],
    ) -> Result<(), ControlError> {
        self.append_access_event_with_evidence_bytes(
            request_id,
            subject_ref,
            MODEL_CALL_ACCESS,
            None,
            None,
            None,
            None,
            Some(target_model_call_id),
            outcome,
            reason_code,
            evidence_refs,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_access_event_with_evidence_bytes(
        &self,
        request_id: &str,
        subject_ref: Option<&str>,
        action: AccessAction,
        target_request_id: Option<&RequestId>,
        target_artifact_id: Option<&ArtifactId>,
        target_case_id: Option<&CaseId>,
        target_access_request_id: Option<&EvidenceAccessRequestId>,
        target_model_call_id: Option<&ModelCallId>,
        outcome: &'static str,
        reason_code: &'static str,
        evidence_refs: &[&str],
        bytes_read: Option<u64>,
        query_digest: Option<&str>,
        target_grant_id: Option<&GrantId>,
        target_binding_id: Option<&AuthBindingId>,
        target_hold_id: Option<&EventId>,
    ) -> Result<(), ControlError> {
        let mut journal = self
            .access_journal
            .lock()
            .map_err(|_| ControlError::LockPoisoned)?;
        let producer_sequence = journal
            .next_sequence()
            .ok_or(ControlError::SequenceExhausted)?;
        let producer_boot_id = journal.producer_boot_id();
        let event_id = EventId::parse(format!("ev_{}", Uuid::now_v7()))
            .map_err(|_| ControlError::InvalidConfig)?;
        let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let trace_id = Uuid::now_v7().simple().to_string();
        let span_id = trace_id[..16].to_owned();
        let event = AccessEvent {
            schema_version: 3,
            event_id: event_id.as_str(),
            event_type: action.event_type,
            tenant_id: self.config.tenant_id.as_str(),
            site_id: self.config.site_id.as_str(),
            request_id,
            trace_id: &trace_id,
            span_id: &span_id,
            producer_id: "xshield-control",
            producer_boot_id: &producer_boot_id,
            producer_seq: producer_sequence,
            request_seq: 1,
            occurred_at: &occurred_at,
            observed_at: &occurred_at,
            policy_revision: "control-v1",
            example_only: false,
            evidence_refs,
            cause_event_ids: &[],
            payload: AccessPayload {
                method: action.method,
                path: action.path,
                subject_ref,
                target_request_id: target_request_id.map(RequestId::as_str),
                target_artifact_id: target_artifact_id.map(ArtifactId::as_str),
                target_case_id: target_case_id.map(CaseId::as_str),
                target_access_request_id: target_access_request_id
                    .map(EvidenceAccessRequestId::as_str),
                target_model_call_id: target_model_call_id.map(ModelCallId::as_str),
                target_grant_id: target_grant_id.map(GrantId::as_str),
                target_binding_id: target_binding_id.map(AuthBindingId::as_str),
                target_hold_id: target_hold_id.map(EventId::as_str),
                query_digest,
                outcome,
                reason_code,
                bytes_read,
            },
            sensitivity: "INTERNAL",
            integrity: PendingIntegrity {
                state: "pending",
                previous_hash: None,
                event_hash: None,
            },
        };
        let bytes = serde_json::to_vec(&event)?;
        let receipts = journal.append_batch(&[JournalRecord {
            event_id: &event_id,
            plaintext: &bytes,
        }])?;
        if receipts.len() != 1 || receipts[0].producer_sequence != producer_sequence {
            return Err(ControlError::ReceiptMismatch);
        }
        Ok(())
    }
}

/// Builds the v1 management router.
///
/// Read routes have no production side effects. Mutations use their documented
/// transactional outbox and every route writes the required management audit.
pub fn router(control: ControlPlane) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health_handler))
        .route(REQUEST_SUMMARY_PATH, get(request_summary_handler))
        .route(REQUEST_EVENTS_PATH, get(request_events_handler))
        .route(MODEL_CALL_PATH, get(model_call_handler))
        .route(
            ledger_inspection::GRANT_PATH,
            get(ledger_inspection::grant_handler),
        )
        .route(
            ledger_inspection::BINDING_PATH,
            get(ledger_inspection::binding_handler),
        )
        .route(
            search::SEARCH_PATH,
            post(search::handler).layer(DefaultBodyLimit::max(search::SEARCH_BODY_BYTES_MAX)),
        )
        .route(REQUEST_EVIDENCE_PATH, get(request_evidence_handler))
        .route(ARTIFACT_PATH, get(artifact_handler))
        .route(EVIDENCE_CONTENT_PATH, get(evidence_content_handler))
        .route(
            evidence_access_inspection::PATH,
            get(evidence_access_inspection::handler).layer(DefaultBodyLimit::max(0)),
        )
        .route(
            evidence_access_list::PATH,
            get(evidence_access_list::handler).layer(DefaultBodyLimit::max(0)),
        )
        .route(
            EVIDENCE_ACCESS_APPROVE_PATH,
            post(evidence_access_approve_handler).layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .route(
            EVIDENCE_ACCESS_DENY_PATH,
            post(evidence_access_deny_handler).layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .route(
            EVIDENCE_ACCESS_PATH,
            post(evidence_access_handler).layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .route(
            CASES_PATH,
            post(create_case_handler)
                .get(case_list::handler)
                .layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .route(
            case_items::PATH,
            post(case_items::handler)
                .get(case_collection::handler)
                .layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .route(
            case_close::PATH,
            post(case_close::handler).layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .route(
            case_holds::PATH,
            post(case_holds::create_handler)
                .get(case_holds::list_handler)
                .layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .route(
            case_holds::RELEASE_PATH,
            post(case_holds::release_handler).layer(DefaultBodyLimit::max(CASE_BODY_BYTES_MAX)),
        )
        .with_state(Arc::new(control))
}

async fn evidence_access_approve_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(access_request_id): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    payload: Result<Json<ApproveEvidenceAccess>, JsonRejection>,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let idempotency_key = single_header(&headers, "idempotency-key");
    control
        .decide_evidence_access(
            EVIDENCE_ACCESS_APPROVE,
            authorization,
            idempotency_key,
            access_request_id,
            payload
                .ok()
                .filter(|_| query.is_none())
                .map(|Json(payload)| EvidenceAccessDecisionInput::Approve(payload)),
        )
        .await
        .into_response()
}

async fn evidence_access_deny_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(access_request_id): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    payload: Result<Json<DenyEvidenceAccess>, JsonRejection>,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let idempotency_key = single_header(&headers, "idempotency-key");
    control
        .decide_evidence_access(
            EVIDENCE_ACCESS_DENY,
            authorization,
            idempotency_key,
            access_request_id,
            payload
                .ok()
                .filter(|_| query.is_none())
                .map(|Json(payload)| EvidenceAccessDecisionInput::Deny(payload)),
        )
        .await
        .into_response()
}

async fn evidence_access_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(artifact_id): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    payload: Result<Json<CreateEvidenceAccessRequest>, JsonRejection>,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let idempotency_key = single_header(&headers, "idempotency-key");
    control
        .request_evidence_access(
            authorization,
            idempotency_key,
            artifact_id,
            payload
                .ok()
                .filter(|_| query.is_none())
                .map(|Json(payload)| payload),
        )
        .await
        .into_response()
}

async fn create_case_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    payload: Result<Json<CreateCaseRequest>, JsonRejection>,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut keys = headers.get_all("idempotency-key").iter();
    let idempotency_key = keys
        .next()
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let idempotency_key = if keys.next().is_none() {
        idempotency_key
    } else {
        None
    };
    control
        .create_case(
            authorization,
            idempotency_key,
            payload.ok().map(|Json(payload)| payload),
        )
        .await
        .into_response()
}

async fn request_summary_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .request_summary(authorization, request_id)
        .await
        .into_response()
}

async fn health_handler(State(control): State<Arc<ControlPlane>>, headers: HeaderMap) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    match tokio::task::spawn_blocking(move || control.health(authorization.as_deref())).await {
        Ok(result) => result.into_response(),
        Err(_) => internal_error(&format!("req_{}", Uuid::now_v7())).into_response(),
    }
}

async fn request_events_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(request_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .request_events(authorization, request_id, raw_query)
        .await
        .into_response()
}

async fn model_call_handler(
    State(control): State<Arc<ControlPlane>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .model_call(authorization, path.ok().map(|Path(id)| id))
        .await
        .into_response()
}

async fn request_evidence_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(request_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .request_evidence(authorization, request_id, raw_query)
        .await
        .into_response()
}

async fn artifact_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(artifact_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    control
        .artifact(authorization, artifact_id)
        .await
        .into_response()
}

async fn evidence_content_handler(
    State(control): State<Arc<ControlPlane>>,
    Path(artifact_id): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let authorization = single_header(&headers, AUTHORIZATION.as_str());
    let access_request_id = single_header(&headers, EVIDENCE_ACCESS_REQUEST_HEADER);
    control
        .read_evidence_content(
            authorization,
            artifact_id,
            access_request_id,
            query.is_some(),
        )
        .await
        .into_response()
}

enum EndpointResult {
    Success(HealthResponse),
    RequestSummary(RequestSummaryResponse),
    RequestEvents(RequestEventsResponse),
    ModelCall(ModelCallResponse),
    Search(search::SearchResponse),
    RequestEvidence(RequestEvidenceResponse),
    Artifact(ArtifactResponse),
    Case(StatusCode, CreateCaseResponse),
    EvidenceAccessRequest(StatusCode, EvidenceAccessRequestResponse),
    EvidenceAccessDecision(EvidenceAccessDecisionResponse),
    Raw(Response),
    Error(StatusCode, ErrorResponse),
}

impl IntoResponse for EndpointResult {
    fn into_response(self) -> Response {
        no_store(match self {
            Self::Success(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::RequestSummary(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::RequestEvents(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::ModelCall(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::Search(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::RequestEvidence(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::Artifact(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::Case(status, response) => (status, Json(response)).into_response(),
            Self::EvidenceAccessRequest(status, response) => {
                (status, Json(response)).into_response()
            }
            Self::EvidenceAccessDecision(response) => {
                (StatusCode::OK, Json(response)).into_response()
            }
            Self::Raw(response) => response,
            Self::Error(status, response) => (status, Json(response)).into_response(),
        })
    }
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorError {
    Invalid,
    Unavailable,
}

fn parse_cursor_query(raw_query: Option<&str>) -> Result<Option<&str>, CursorError> {
    let Some(raw_query) = raw_query else {
        return Ok(None);
    };
    let cursor = raw_query
        .strip_prefix("cursor=")
        .filter(|cursor| !cursor.is_empty() && cursor.len() <= CURSOR_BYTES_MAX)
        .ok_or(CursorError::Invalid)?;
    Ok(Some(cursor))
}

#[allow(clippy::too_many_arguments)]
fn cursor_signature(
    key: &[u8; 32],
    credential_digest: &[u8; 32],
    subject: &str,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
    limit: u16,
    position: &RequestEventPosition,
) -> Result<[u8; 32], ()> {
    let limit = limit.to_be_bytes();
    let request_seq = position.request_seq().to_be_bytes();
    component_signature(
        key,
        &[
            b"xshield-control-events-cursor-v1".as_slice(),
            credential_digest,
            subject.as_bytes(),
            tenant_id.as_str().as_bytes(),
            site_id.as_str().as_bytes(),
            request_id.as_str().as_bytes(),
            &limit,
            &request_seq,
            position.event_id().as_str().as_bytes(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn evidence_cursor_signature(
    key: &[u8; 32],
    credential_digest: &[u8; 32],
    subject: &str,
    tenant_id: &TenantId,
    site_id: &SiteId,
    request_id: &RequestId,
    limit: u16,
    artifact_id: &ArtifactId,
) -> Result<[u8; 32], ()> {
    let limit = limit.to_be_bytes();
    component_signature(
        key,
        &[
            b"xshield-control-evidence-cursor-v1",
            credential_digest,
            subject.as_bytes(),
            tenant_id.as_str().as_bytes(),
            site_id.as_str().as_bytes(),
            request_id.as_str().as_bytes(),
            &limit,
            artifact_id.as_str().as_bytes(),
        ],
    )
}

// Security-relevant fields must identify one value, including when duplicates
// happen to carry the same bytes. Do not let HTTP intermediaries choose one.
fn single_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn case_created_envelope(
    event_id: &EventId,
    request_id: &RequestId,
    draft: &InvestigationCaseDraft,
    request_digest: &[u8; 32],
) -> serde_json::Value {
    let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_id = Uuid::now_v7().simple().to_string();
    serde_json::json!({
        "schema_version": 3,
        "event_id": event_id.as_str(),
        "event_type": "case.created",
        "tenant_id": draft.tenant_id().as_str(),
        "site_id": draft.site_id().as_str(),
        "request_id": request_id.as_str(),
        "trace_id": trace_id,
        "span_id": &trace_id[..16],
        "producer_id": "xshield-control",
        "producer_boot_id": request_id.as_str(),
        "producer_seq": 1,
        "request_seq": 1,
        "occurred_at": occurred_at,
        "observed_at": occurred_at,
        "policy_revision": "control-v1",
        "example_only": false,
        "evidence_refs": [],
        "cause_event_ids": [],
        "payload": {
            "stage": "case_management",
            "case_id": draft.case_id().as_str(),
            "subject_ref": draft.owner_ref(),
            "request_digest": lower_hex(request_digest),
            "outcome": "PASS",
            "reason_code": "CASE_CREATED"
        },
        "sensitivity": "INTERNAL",
        "integrity": {
            "state": "pending",
            "previous_hash": null,
            "event_hash": null
        }
    })
}

fn evidence_access_requested_envelope(
    event_id: &EventId,
    request_id: &RequestId,
    draft: &EvidenceAccessRequestDraft,
    request_digest: &[u8; 32],
) -> serde_json::Value {
    let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_id = Uuid::now_v7().simple().to_string();
    serde_json::json!({
        "schema_version": 3,
        "event_id": event_id.as_str(),
        "event_type": "evidence.access.requested",
        "tenant_id": draft.tenant_id().as_str(),
        "site_id": draft.site_id().as_str(),
        "request_id": request_id.as_str(),
        "trace_id": trace_id,
        "span_id": &trace_id[..16],
        "producer_id": "xshield-control",
        "producer_boot_id": request_id.as_str(),
        "producer_seq": 1,
        "request_seq": 1,
        "occurred_at": occurred_at,
        "observed_at": occurred_at,
        "policy_revision": "control-v1",
        "example_only": false,
        "evidence_refs": [draft.artifact_id().as_str()],
        "cause_event_ids": [],
        "payload": {
            "stage": "evidence_access",
            "access_request_id": draft.access_request_id().as_str(),
            "case_id": draft.case_id().as_str(),
            "artifact_id": draft.artifact_id().as_str(),
            "subject_ref": draft.requested_by(),
            "access_kind": draft.kind().as_str(),
            "request_digest": lower_hex(request_digest),
            "outcome": "PASS",
            "reason_code": "EVIDENCE_ACCESS_REQUESTED"
        },
        "sensitivity": "INTERNAL",
        "integrity": {
            "state": "pending",
            "previous_hash": null,
            "event_hash": null
        }
    })
}

fn evidence_access_decision_envelope(
    event_id: &EventId,
    request_id: &RequestId,
    decision: &EvidenceAccessDecisionDraft,
    request_digest: &[u8; 32],
) -> serde_json::Value {
    let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_id = Uuid::now_v7().simple().to_string();
    serde_json::json!({
        "schema_version": 3,
        "event_id": event_id.as_str(),
        "event_type": decision.kind().event_type(),
        "tenant_id": decision.tenant_id().as_str(),
        "site_id": decision.site_id().as_str(),
        "request_id": request_id.as_str(),
        "trace_id": trace_id,
        "span_id": &trace_id[..16],
        "producer_id": "xshield-control",
        "producer_boot_id": request_id.as_str(),
        "producer_seq": 1,
        "request_seq": 1,
        "occurred_at": occurred_at,
        "observed_at": occurred_at,
        "policy_revision": "control-v1",
        "example_only": false,
        "evidence_refs": [],
        "cause_event_ids": [],
        "payload": {
            "stage": "evidence_access_decision",
            "access_request_id": decision.access_request_id().as_str(),
            "subject_ref": decision.decided_by(),
            "decision": decision.kind().as_str(),
            "ttl_seconds": decision.requested_ttl_seconds(),
            "request_digest": lower_hex(request_digest),
            "outcome": "PASS",
            "reason_code": decision.kind().reason_code()
        },
        "sensitivity": "INTERNAL",
        "integrity": {
            "state": "pending",
            "previous_hash": null,
            "event_hash": null
        }
    })
}

fn component_signature(key: &[u8; 32], components: &[&[u8]]) -> Result<[u8; 32], ()> {
    let key = PKey::hmac(key).map_err(|_| ())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).map_err(|_| ())?;
    for component in components {
        signer
            .update(&(component.len() as u64).to_be_bytes())
            .map_err(|_| ())?;
        signer.update(component).map_err(|_| ())?;
    }
    signer
        .sign_to_vec()
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

fn parse_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut decoded = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Some(decoded)
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn lower_hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn audit_unavailable(request_id: &str) -> EndpointResult {
    api_error(
        request_id,
        StatusCode::SERVICE_UNAVAILABLE,
        "AUDIT_DURABILITY_FAILED",
        "required management audit is unavailable",
        true,
        "retry_later",
    )
}

fn internal_error(request_id: &str) -> EndpointResult {
    api_error(
        request_id,
        StatusCode::SERVICE_UNAVAILABLE,
        "CONTROL_INTERNAL",
        "management service unavailable",
        true,
        "retry_later",
    )
}

fn api_error(
    request_id: &str,
    status: StatusCode,
    error_code: &'static str,
    message_safe: &'static str,
    retryable: bool,
    next_action: &'static str,
) -> EndpointResult {
    EndpointResult::Error(
        status,
        ErrorResponse {
            error_code,
            message_safe,
            request_id: request_id.to_owned(),
            retryable,
            next_action,
        },
    )
}

#[derive(Serialize)]
struct HealthResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    #[serde(flatten)]
    health: PublicationHealth,
}

#[derive(Serialize)]
struct RequestEventsResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_request_id: String,
    as_of: String,
    index_watermark: Option<IndexWatermark>,
    has_gaps: bool,
    next_cursor: Option<String>,
    #[serde(flatten)]
    events: RequestEvents,
}

#[derive(Serialize)]
struct ModelCallResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_model_call_id: String,
    watermark_scope: &'static str,
    as_of: String,
    index_watermark: Option<IndexWatermark>,
    has_gaps: bool,
    pending_segments: usize,
    found: bool,
    completeness: &'static str,
    model_call: Option<ModelCallSummary>,
}

fn model_call_evidence_refs(summary: &ModelCallSummary) -> Vec<String> {
    // The query validates that all top-level artifacts occur in these envelopes.
    let mut refs: Vec<_> = summary
        .events
        .iter()
        .flat_map(|event| event.evidence_refs.iter().cloned())
        .collect();
    refs.sort_unstable();
    refs.dedup();
    refs
}

#[derive(Serialize)]
struct RequestSummaryResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_request_id: String,
    as_of: String,
    index_watermark: Option<IndexWatermark>,
    has_gaps: bool,
    pending_segments: usize,
    found: bool,
    completeness: &'static str,
    summary: Option<RequestSummary>,
}

#[derive(Serialize)]
struct RequestEvidenceResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_request_id: String,
    truncated: bool,
    next_cursor: Option<String>,
    artifacts: Vec<EvidenceArtifactResponse>,
}

#[derive(Serialize)]
struct EvidenceArtifactResponse {
    recorded_at: String,
    #[serde(flatten)]
    manifest: EvidenceManifest,
}

fn evidence_artifact_response(
    artifact: &xshield_postgres::CatalogArtifact,
) -> EvidenceArtifactResponse {
    EvidenceArtifactResponse {
        recorded_at: artifact
            .recorded_at()
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        manifest: artifact.manifest().clone(),
    }
}

#[derive(Serialize)]
struct ArtifactResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    source_artifact_id: String,
    found: bool,
    artifact: Option<EvidenceArtifactResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCaseRequest {
    purpose: String,
}

#[derive(Serialize)]
struct CreateCaseResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    case_id: String,
    status: &'static str,
    purpose: String,
    created_at: String,
    replayed: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceAccessKindRequest {
    SensitiveRaw,
}

impl From<EvidenceAccessKindRequest> for EvidenceAccessKind {
    fn from(value: EvidenceAccessKindRequest) -> Self {
        match value {
            EvidenceAccessKindRequest::SensitiveRaw => Self::SensitiveRaw,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEvidenceAccessRequest {
    case_id: String,
    access_kind: EvidenceAccessKindRequest,
    justification: String,
}

#[derive(Serialize)]
struct EvidenceAccessRequestResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    access_request_id: String,
    case_id: String,
    artifact_id: String,
    access_kind: &'static str,
    status: &'static str,
    requested_at: String,
    replayed: bool,
}

enum EvidenceAccessDecisionInput {
    Approve(ApproveEvidenceAccess),
    Deny(DenyEvidenceAccess),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveEvidenceAccess {
    reason: String,
    ttl_seconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DenyEvidenceAccess {
    reason: String,
}

#[derive(Serialize)]
struct EvidenceAccessDecisionResponse {
    request_id: String,
    tenant_id: String,
    site_id: String,
    access_request_id: String,
    case_id: String,
    artifact_id: String,
    requested_by: String,
    decided_by: String,
    status: &'static str,
    decided_at: String,
    access_expires_at: Option<String>,
    replayed: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error_code: &'static str,
    message_safe: &'static str,
    request_id: String,
    retryable: bool,
    next_action: &'static str,
}

struct RateWindow {
    started_at: Instant,
    used: u64,
    limit: u64,
}

impl RateWindow {
    fn new(limit: u64) -> Self {
        Self {
            started_at: Instant::now(),
            used: 0,
            limit,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        if now.duration_since(self.started_at) >= RATE_WINDOW {
            self.started_at = now;
            self.used = 0;
        }
        if self.used >= self.limit {
            return false;
        }
        self.used += 1;
        true
    }
}

#[derive(Serialize)]
struct AccessEvent<'a> {
    schema_version: u8,
    event_id: &'a str,
    event_type: &'a str,
    tenant_id: &'a str,
    site_id: &'a str,
    request_id: &'a str,
    trace_id: &'a str,
    span_id: &'a str,
    producer_id: &'a str,
    producer_boot_id: &'a str,
    producer_seq: u64,
    request_seq: u8,
    occurred_at: &'a str,
    observed_at: &'a str,
    policy_revision: &'a str,
    example_only: bool,
    evidence_refs: &'a [&'a str],
    cause_event_ids: &'a [&'a str],
    payload: AccessPayload<'a>,
    sensitivity: &'a str,
    integrity: PendingIntegrity<'a>,
}

#[derive(Serialize)]
struct AccessPayload<'a> {
    method: &'a str,
    path: &'a str,
    subject_ref: Option<&'a str>,
    target_request_id: Option<&'a str>,
    target_artifact_id: Option<&'a str>,
    target_case_id: Option<&'a str>,
    target_access_request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_model_call_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_grant_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_binding_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_hold_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_digest: Option<&'a str>,
    outcome: &'a str,
    reason_code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_read: Option<u64>,
}

#[derive(Serialize)]
struct PendingIntegrity<'a> {
    state: &'a str,
    previous_hash: Option<&'a str>,
    event_hash: Option<&'a str>,
}

/// Startup or durability failure for the control-plane service.
#[derive(Debug)]
pub enum ControlError {
    /// A trusted startup scalar violates its contract.
    InvalidConfig,
    /// The access-journal mutex was poisoned.
    LockPoisoned,
    /// The local producer sequence cannot advance.
    SequenceExhausted,
    /// A durable receipt does not match the submitted event.
    ReceiptMismatch,
    /// Local encrypted journal failure.
    Journal(JournalError),
    /// Audit event serialization failure.
    Json(serde_json::Error),
    /// Publication-health evidence failure.
    Publisher(PublishError),
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid control configuration"),
            Self::LockPoisoned => formatter.write_str("control audit lock poisoned"),
            Self::SequenceExhausted => formatter.write_str("control audit sequence exhausted"),
            Self::ReceiptMismatch => formatter.write_str("control audit receipt mismatch"),
            Self::Journal(error) => error.fmt(formatter),
            Self::Json(_) => formatter.write_str("control audit serialization failed"),
            Self::Publisher(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Publisher(error) => Some(error),
            Self::InvalidConfig
            | Self::LockPoisoned
            | Self::SequenceExhausted
            | Self::ReceiptMismatch => None,
        }
    }
}

impl From<JournalError> for ControlError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<serde_json::Error> for ControlError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[cfg(test)]
mod tests {
    mod access_console_wire;
    mod audit_publish;
    mod case_close;
    mod case_collection;
    mod case_console_wire;
    mod case_holds;
    mod case_holds_postgres;
    mod case_items;
    mod case_list;
    mod evidence_access_inspection;
    mod evidence_access_list;
    mod evidence_lifecycle;
    mod ledger_inspection;
    mod search_references;

    use super::search::SearchRequest;
    use super::{
        ControlConfig, ControlLimits, ControlPlane, CursorKey, EVIDENCE_ACCESS_REQUEST_HEADER,
        EvidenceReadPort, IdempotencyKey, ManagementCredential, router,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{
            Request, StatusCode,
            header::{AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_TYPE},
        },
    };
    use chrono::{DateTime, SecondsFormat, Utc};
    use clickhouse::{Client, Row, test};
    use serde::Serialize;
    use serde_json::{Value, json};
    use std::{
        fs,
        path::Path,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;
    use uuid::Uuid;
    use xshield_audit::{
        JournalKey, JournalLimits, LocalJournal, SealSigningKey, SealVerifyingKey,
        SealedSegmentReader, seal_closed_segments,
    };
    use xshield_core::{
        admin::{ManagementPrincipal, ManagementRole},
        domain::{EventId, RequestId, SiteId, TenantId},
    };
    use xshield_evidence::{
        EvidenceClassification, EvidenceFidelity, EvidenceKey, EvidenceVaultConfig, EvidenceWrite,
        LocalEvidenceVault,
    };
    use xshield_postgres::{
        EvidenceCatalogPublish, EvidenceCatalogWriteOutcome, PostgresIdentityStore,
    };
    use xshield_worker::{
        AuditEventSummary, PublisherConfig, RequestEventPosition, RequestStageSummary,
    };

    const JOURNAL_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SEAL_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const CURSOR_KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const IDEMPOTENCY_KEY: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";
    const TOKEN: &str = "test-control-token-32-bytes-long-value";
    const MODEL_CALL_ID: &str = "mdl_018f2a3b-4c5d-7000-8000-000000000001";
    const MISSING_ARTIFACT_ID: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000999";

    #[test]
    fn evidence_response_owns_plaintext_and_admission_until_last_clone() {
        for plaintext in [vec![], vec![7; 1024]] {
            let capacity = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
            let pointer = plaintext.as_ptr();
            let content = super::EvidenceContent {
                bytes: zeroize::Zeroizing::new(plaintext),
                _permit: capacity.clone().try_acquire_owned().unwrap(),
            };
            let bytes = axum::body::Bytes::from_owner(content);
            assert_eq!(bytes.as_ptr(), pointer, "plaintext must not be copied");
            let retained = bytes.clone();
            drop(bytes);
            assert!(capacity.clone().try_acquire_owned().is_err());
            drop(retained);
            assert_eq!(capacity.available_permits(), 1);
        }
    }

    #[tokio::test]
    async fn cancelled_evidence_task_keeps_admission_until_blocking_work_finishes() {
        let capacity = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = capacity.clone().try_acquire_owned().unwrap();
        let (started, start) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (finished, finish) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(super::EvidenceContent {
                bytes: zeroize::Zeroizing::new(vec![7; 1024]),
                _permit: permit,
            });
            finished.send(()).unwrap();
        });
        start.await.unwrap();
        task.abort();
        drop(task);
        assert!(capacity.clone().try_acquire_owned().is_err());
        release.send(()).unwrap();
        finish.await.unwrap();
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn enforces_auth_scope_rate_limit_and_health_contract() {
        assert!(CursorKey::from_hex("not-a-key").is_err());
        assert!(IdempotencyKey::from_hex("not-a-key").is_err());
        assert!(!super::distinct_control_keys(
            &CursorKey::from_hex(CURSOR_KEY).unwrap(),
            &IdempotencyKey::from_hex(CURSOR_KEY).unwrap(),
        ));
        assert!(super::distinct_control_keys(
            &CursorKey::from_hex(CURSOR_KEY).unwrap(),
            &IdempotencyKey::from_hex(IDEMPOTENCY_KEY).unwrap(),
        ));
        assert!(ControlLimits::new(0, 100, 1, 1, 1, 1).is_err());
        assert!(ControlLimits::new(1, 1_001, 1, 1, 1, 1).is_err());
        assert!(ControlLimits::new(1, 1, 129, 1, 1, 1).is_err());
        assert!(ControlLimits::new(1, 1, 1, 0, 1, 1).is_err());
        assert!(ControlLimits::new(1, 1, 1, 10_001, 1, 1).is_err());
        assert!(ControlLimits::new(1, 1, 1, 1, 0, 1).is_err());
        assert!(ControlLimits::new(1, 1, 1, 1, 10_001, 1).is_err());
        assert!(ControlLimits::new(1, 1, 1, 1, 1, 0).is_err());
        assert!(ControlLimits::new(1, 1, 1, 1, 1, 86_401).is_err());
        assert!(
            ManagementCredential::new(
                TOKEN,
                1,
                super::TOKEN_LIFETIME_MAX_SECONDS.saturating_add(2),
            )
            .is_err()
        );
        let fixture = Fixture::new(1, ManagementRole::AuditAdministrator);
        let app = router(fixture.control);

        let unauthorized = app
            .clone()
            .oneshot(
                Request::get(super::HEALTH_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let unauthenticated_limited = app
            .clone()
            .oneshot(
                Request::get(super::HEALTH_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            unauthenticated_limited.status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        let allowed = app.clone().oneshot(authenticated_request()).await.unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(allowed.headers()["cache-control"], "private, no-store");
        let body = to_bytes(allowed.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["tenant_id"], "tenant_a");
        assert_eq!(body["site_id"], "site_a");
        assert_eq!(body["closed_segments"], 0);
        assert_eq!(body["metadata_retention_days"], 30);

        let limited = app.oneshot(authenticated_request()).await.unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_access_events(&fixture.access_directory, 3, "console.health.read", None);

        let forbidden = router(Fixture::new(10, ManagementRole::Observer).control)
            .oneshot(authenticated_request())
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired = router(
            Fixture::with_window(10, ManagementRole::AuditAdministrator, now - 60, now - 1).control,
        )
        .oneshot(authenticated_request())
        .await
        .unwrap();
        assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn model_call_endpoint_returns_refs_and_audits_scope() {
        let model_call_id = "mdl_018f2a3b-4c5d-7000-8000-000000000001";
        let input_id = "artifact_018f2a3b-4c5d-7000-8000-000000000001";
        let output_id = "artifact_018f2a3b-4c5d-7000-8000-000000000002";
        let call_id = "artifact_018f2a3b-4c5d-7000-8000-000000000003";
        let request_id = "req_018f2a3b-4c5d-7000-8000-000000000001";
        let payload = serde_json::json!({
            "model_call_id": model_call_id,
            "provider": "vercel_ai_gateway",
            "provider_model_id": "typesafe-ai/jev",
            "model_revision": "jev-1.13.0",
            "prompt_revision": "evaluation-r1",
            "question_type": "choice",
            "status": "success",
            "reason_code": "MODEL_EVALUATED",
            "confidence": 0.8,
            "confidence_status": "provided",
            "duration_us": 1200,
            "input_artifact_id": input_id,
            "output_artifact_id": output_id,
            "call_artifact_id": call_id
        })
        .to_string();
        let mock = test::Mock::new();
        mock.add(test::handlers::provide([ModelRow {
            event_id: "ev_018f2a3b-4c5d-7000-8000-000000000001".to_owned(),
            event_type: "model.responded".to_owned(),
            request_id: request_id.to_owned(),
            occurred_at: Utc::now(),
            request_seq: 1,
            evidence_refs: vec![
                input_id.to_owned(),
                output_id.to_owned(),
                call_id.to_owned(),
            ],
            cause_event_ids: vec!["ev_018f2a3b-4c5d-7000-8000-000000000002".into()],
            sensitivity: "RESTRICTED".to_owned(),
            payload_json: payload,
        }]));
        let fixture = Fixture::with_index(
            10,
            ManagementRole::Observer,
            Client::default().with_mock(&mock),
        );
        let response = router(fixture.control)
            .oneshot(
                Request::get(format!("/control/v1/model-calls/{model_call_id}"))
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["found"], true);
        assert_eq!(body["completeness"], "partial");
        assert_eq!(body["watermark_scope"], "configured_journal");
        assert_eq!(body["model_call"]["input_artifact_id"], input_id);
        assert_eq!(body["model_call"]["output_artifact_id"], output_id);
        assert_eq!(body["model_call"]["call_artifact_id"], call_id);
        assert_eq!(body["model_call"]["provider"], "vercel_ai_gateway");
        assert_eq!(body["model_call"]["provider_model_id"], "typesafe-ai/jev");
        let audit = read_access_events(&fixture.access_directory);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0]["event_type"], "console.model.read");
        assert_eq!(audit[0]["evidence_refs"].as_array().unwrap().len(), 3);
        assert_eq!(audit[0]["payload"]["target_model_call_id"], model_call_id);
    }

    #[tokio::test]
    async fn model_call_rejects_unauthorized_and_invalid_ids_before_index_access() {
        for (role, authenticated, id, expected) in [
            (
                ManagementRole::Observer,
                false,
                "%FF",
                StatusCode::UNAUTHORIZED,
            ),
            (
                ManagementRole::AuditAdministrator,
                true,
                MODEL_CALL_ID,
                StatusCode::FORBIDDEN,
            ),
            (
                ManagementRole::Observer,
                true,
                "invalid",
                StatusCode::BAD_REQUEST,
            ),
            (
                ManagementRole::Observer,
                true,
                "%FF",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let mock = test::Mock::new();
            let fixture = Fixture::with_index(10, role, Client::default().with_mock(&mock));
            let mut request = Request::get(format!("/control/v1/model-calls/{id}"))
                .body(Body::empty())
                .unwrap();
            if authenticated {
                request
                    .headers_mut()
                    .insert(AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
            }
            let response = router(fixture.control).oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()["cache-control"], "private, no-store");
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            if expected == StatusCode::BAD_REQUEST {
                assert_eq!(body["error_code"], "CONTROL_MODEL_CALL_ID_INVALID");
            }
            assert_access_events(&fixture.access_directory, 1, "console.model.read", None);
        }
    }

    #[tokio::test]
    async fn model_call_miss_is_not_a_producer_absence_claim() {
        let mock = test::Mock::new();
        mock.add(test::handlers::provide(Vec::<ModelRow>::new()));
        let fixture = Fixture::with_index(
            10,
            ManagementRole::Observer,
            Client::default().with_mock(&mock),
        );
        let response = router(fixture.control)
            .oneshot(analytical_http_request(true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["found"], false);
        assert_eq!(body["completeness"], "not_indexed");
        assert_eq!(body["watermark_scope"], "configured_journal");
        assert!(body["model_call"].is_null());
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["payload"]["target_model_call_id"], MODEL_CALL_ID);
        assert_eq!(events[0]["evidence_refs"], json!([]));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn request_events_are_scoped_bounded_and_audited() {
        let mock = test::Mock::new();
        mock.add(test::handlers::provide([
            event_summary("ev_018f2a3b-4c5d-7000-8000-000000000001", 1),
            event_summary("ev_018f2a3b-4c5d-7000-8000-000000000002", 2),
        ]));
        mock.add(test::handlers::provide([event_summary(
            "ev_018f2a3b-4c5d-7000-8000-000000000002",
            2,
        )]));
        let fixture = Fixture::with_index(
            10,
            ManagementRole::Observer,
            Client::default().with_mock(&mock),
        );
        let position = RequestEventPosition::new(
            1,
            EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
        )
        .unwrap();
        let target = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
        let cursor = fixture
            .control
            .encode_cursor("operator-1", &target, &position)
            .unwrap();
        assert_eq!(
            fixture
                .control
                .decode_cursor("operator-1", &target, &cursor)
                .unwrap(),
            position
        );
        let other_target = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000002").unwrap();
        assert!(
            fixture
                .control
                .decode_cursor("operator-1", &other_target, &cursor)
                .is_err()
        );
        let path = "/control/v1/requests/req_018f2a3b-4c5d-7000-8000-000000000001/events";
        let app = router(fixture.control);
        let response = app
            .clone()
            .oneshot(
                Request::get(path)
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["tenant_id"], "tenant_a");
        assert_eq!(body["site_id"], "site_a");
        assert_eq!(body["events"][0]["request_seq"], 1);
        assert_eq!(body["truncated"], true);
        let returned_cursor = body["next_cursor"].as_str().unwrap();
        assert_eq!(returned_cursor, cursor);
        assert!(body["events"][0].get("payload_json").is_none());
        assert_access_events(
            &fixture.access_directory,
            1,
            "console.events.read",
            Some("req_018f2a3b-4c5d-7000-8000-000000000001"),
        );
        let next_page = app
            .clone()
            .oneshot(
                Request::get(format!("{path}?cursor={returned_cursor}"))
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(next_page.status(), StatusCode::OK);
        let body = to_bytes(next_page.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["events"][0]["request_seq"], 2);
        assert_eq!(body["truncated"], false);
        assert!(body["next_cursor"].is_null());
        let wrong_scope_cursor = app
            .oneshot(
                Request::get(format!(
                    "/control/v1/requests/{}/events?cursor={cursor}",
                    other_target.as_str()
                ))
                .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_scope_cursor.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(wrong_scope_cursor.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "CONTROL_CURSOR_INVALID");

        let forbidden = router(Fixture::new(10, ManagementRole::AuditAdministrator).control)
            .oneshot(
                Request::get(path)
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let invalid_fixture = Fixture::new(10, ManagementRole::Observer);
        let invalid = router(invalid_fixture.control)
            .oneshot(
                Request::get("/control/v1/requests/not-a-request/events")
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_access_events(
            &invalid_fixture.access_directory,
            1,
            "console.events.read",
            None,
        );

        let failing_mock = test::Mock::new();
        failing_mock.add(test::handlers::exception(209));
        let failing_fixture = Fixture::with_index(
            10,
            ManagementRole::Observer,
            Client::default().with_mock(&failing_mock),
        );
        let unavailable = router(failing_fixture.control)
            .oneshot(
                Request::get(path)
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_access_events(
            &failing_fixture.access_directory,
            1,
            "console.events.read",
            Some("req_018f2a3b-4c5d-7000-8000-000000000001"),
        );
    }

    #[tokio::test]
    async fn request_summary_reports_completeness_and_is_audited() {
        let mock = test::Mock::new();
        mock.add(test::handlers::provide([SummaryRow {
            event_count: 4,
            first_occurred_at: Utc::now(),
            last_occurred_at: Utc::now(),
            method: "POST".to_owned(),
            operation_id: "orders.create".to_owned(),
            decision: "ALLOW".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            status: Some(201),
            origin_state: "response_received".to_owned(),
            duration_us: 42,
            forwarded: 1,
            terminal: 1,
        }]));
        mock.add(test::handlers::provide([RequestStageSummary {
            stage: "admission".to_owned(),
            outcome: "PASS".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            proof_kind: "deterministic".to_owned(),
            confidence: None,
            confidence_status: "not_applicable".to_owned(),
            first_request_seq: 2,
            last_request_seq: 2,
            duration_us: 10,
            event_count: 1,
        }]));
        mock.add(test::handlers::provide(Vec::<SummaryRow>::new()));
        let fixture = Fixture::with_index(
            10,
            ManagementRole::Observer,
            Client::default().with_mock(&mock),
        );
        let path = "/control/v1/requests/req_018f2a3b-4c5d-7000-8000-000000000001";
        let app = router(fixture.control);
        let response = app
            .clone()
            .oneshot(
                Request::get(path)
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["found"], true);
        assert_eq!(body["completeness"], "complete");
        assert_eq!(body["summary"]["method"], "POST");
        assert_eq!(body["summary"]["business_result_confirmed"], true);
        assert_eq!(body["summary"]["stages"][0]["stage"], "admission");
        assert!(body["summary"].get("payload_json").is_none());
        let missing = app
            .oneshot(
                Request::get("/control/v1/requests/req_018f2a3b-4c5d-7000-8000-000000000002")
                    .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(missing.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["found"], false);
        assert_eq!(body["completeness"], "not_found");
        assert_access_event_targets(
            &fixture.access_directory,
            "console.request.read",
            &[
                Some("req_018f2a3b-4c5d-7000-8000-000000000001"),
                Some("req_018f2a3b-4c5d-7000-8000-000000000002"),
            ],
        );
    }

    #[tokio::test]
    async fn artifact_lookup_validates_identity_and_audits_catalog_failure() {
        let invalid_fixture = Fixture::new(10, ManagementRole::Observer);
        let invalid = router(invalid_fixture.control)
            .oneshot(authenticated_path("/control/v1/artifacts/not-an-artifact"))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_access_event_targets_and_evidence(
            &invalid_fixture.access_directory,
            "console.manifest.read",
            &[None],
            &[None],
            &[None],
            &[None],
            &[0],
        );

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let unavailable_fixture = Fixture::with_catalog(
            10,
            ManagementRole::Observer,
            PostgresIdentityStore::from_pool(pool),
            1,
        );
        let artifact_id = "artifact_018f2a3b-4c5d-7000-8000-000000000998";
        let unavailable = router(unavailable_fixture.control)
            .oneshot(authenticated_path(&format!(
                "/control/v1/artifacts/{artifact_id}"
            )))
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(unavailable.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "CONTROL_CATALOG_UNAVAILABLE");
        assert_access_event_targets_and_evidence(
            &unavailable_fixture.access_directory,
            "console.manifest.read",
            &[None],
            &[Some(artifact_id)],
            &[None],
            &[None],
            &[0],
        );
    }

    #[tokio::test]
    async fn case_creation_enforces_role_input_and_store_availability() {
        let invalid_key = Fixture::new(10, ManagementRole::Investigator);
        let response = router(invalid_key.control)
            .oneshot(case_request("short", r#"{"purpose":"Review anomaly"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_case_access_events(&invalid_key.access_directory, &[None]);

        let invalid_body = Fixture::new(10, ManagementRole::Investigator);
        let response = router(invalid_body.control)
            .oneshot(case_request(
                "case-request-key-0001",
                r#"{"purpose":"Review anomaly","scope":"untrusted"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_case_access_events(&invalid_body.access_directory, &[None]);

        let forbidden = Fixture::new(10, ManagementRole::Observer);
        let response = router(forbidden.control)
            .oneshot(case_request(
                "case-request-key-0002",
                r#"{"purpose":"Review anomaly"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_case_access_events(&forbidden.access_directory, &[None]);

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let unavailable = Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool), 1);
        let response = router(unavailable.control)
            .oneshot(case_request(
                "case-request-key-0003",
                r#"{"purpose":"Review anomaly"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "CONTROL_CASE_STORE_UNAVAILABLE");
        assert_case_access_events(&unavailable.access_directory, &[None]);
    }

    #[tokio::test]
    #[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
    async fn case_creation_is_idempotent_bounded_and_audited() {
        let database_url =
            std::env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
        let catalog = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
            .await
            .expect("case store connects");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("assertion pool connects");
        sqlx::query(
            "DELETE FROM xshield.investigation_cases
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM xshield.audit_outbox
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND event_type = 'case.created'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let fixture = Fixture::with_case_catalog(catalog, 1);
        let app = router(fixture.control);
        let first = app
            .clone()
            .oneshot(case_request(
                "case-request-key-1001",
                r#"{"purpose":"Review evidence anomaly"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        assert_eq!(first.headers()["cache-control"], "private, no-store");
        let first: Value =
            serde_json::from_slice(&to_bytes(first.into_body(), 16 * 1024).await.unwrap()).unwrap();
        let case_id = first["case_id"].as_str().unwrap().to_owned();
        assert_eq!(first["status"], "open");
        assert_eq!(first["replayed"], false);

        let retry = app
            .clone()
            .oneshot(case_request(
                "case-request-key-1001",
                r#"{"purpose":"Review evidence anomaly"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        let retry: Value =
            serde_json::from_slice(&to_bytes(retry.into_body(), 16 * 1024).await.unwrap()).unwrap();
        assert_eq!(retry["case_id"], case_id);
        assert_eq!(retry["replayed"], true);

        let conflict = app
            .clone()
            .oneshot(case_request(
                "case-request-key-1001",
                r#"{"purpose":"Different purpose"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let capacity = app
            .oneshot(case_request(
                "case-request-key-1002",
                r#"{"purpose":"Second case"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(capacity.status(), StatusCode::TOO_MANY_REQUESTS);

        let envelope: Value = sqlx::query_scalar(
            "SELECT envelope FROM xshield.audit_outbox
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND aggregate_ref = $1 AND event_type = 'case.created'",
        )
        .bind(&case_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(envelope["payload"]["case_id"], case_id);
        assert_eq!(envelope["payload"]["subject_ref"], "operator-1");
        assert_eq!(envelope["payload"]["reason_code"], "CASE_CREATED");
        assert!(envelope["payload"]["request_digest"].as_str().is_some());
        assert!(!envelope.to_string().contains("case-request-key"));
        assert_case_access_events(
            &fixture.access_directory,
            &[Some(&case_id), Some(&case_id), None, None],
        );
    }

    #[tokio::test]
    async fn evidence_access_request_enforces_role_input_and_store_availability() {
        let invalid = Fixture::new(10, ManagementRole::Investigator);
        let response = router(invalid.control)
            .oneshot(evidence_access_request(
                "not-an-artifact",
                "evidence-access-key-0001",
                r#"{"case_id":"bad","access_kind":"sensitive_raw","justification":"Review"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let unknown_field = Fixture::new(10, ManagementRole::Investigator);
        let response = router(unknown_field.control)
            .oneshot(evidence_access_request(
                MISSING_ARTIFACT_ID,
                "evidence-access-key-0002",
                r#"{"case_id":"case_018f2a3b-4c5d-7000-8000-000000000991","access_kind":"sensitive_raw","justification":"Review","scope":"untrusted"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let forbidden = Fixture::new(10, ManagementRole::Observer);
        let response = router(forbidden.control)
            .oneshot(evidence_access_request(
                MISSING_ARTIFACT_ID,
                "evidence-access-key-0003",
                r#"{"case_id":"case_018f2a3b-4c5d-7000-8000-000000000991","access_kind":"sensitive_raw","justification":"Review"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let unavailable = Fixture::with_case_catalog(PostgresIdentityStore::from_pool(pool), 1);
        let response = router(unavailable.control)
            .oneshot(evidence_access_request(
                MISSING_ARTIFACT_ID,
                "evidence-access-key-0004",
                r#"{"case_id":"case_018f2a3b-4c5d-7000-8000-000000000991","access_kind":"sensitive_raw","justification":"Review"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["error_code"],
            "CONTROL_EVIDENCE_ACCESS_STORE_UNAVAILABLE"
        );
    }

    #[tokio::test]
    async fn evidence_content_enforces_role_input_and_store_availability() {
        let access_id = "access_018f2a3b-4c5d-7000-8000-000000000981";
        let forbidden = Fixture::new(10, ManagementRole::Observer);
        let response = router(forbidden.control)
            .oneshot(evidence_content_request(MISSING_ARTIFACT_ID, access_id))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let invalid = Fixture::new(10, ManagementRole::SensitiveEvidenceReader);
        let app = router(invalid.control);
        for (artifact, access, expected) in [
            (
                "bad",
                Some(access_id),
                "CONTROL_EVIDENCE_ARTIFACT_ID_INVALID",
            ),
            (
                MISSING_ARTIFACT_ID,
                None,
                "CONTROL_EVIDENCE_ACCESS_REQUEST_REQUIRED",
            ),
            (
                MISSING_ARTIFACT_ID,
                Some("bad"),
                "CONTROL_EVIDENCE_ACCESS_REQUEST_ID_INVALID",
            ),
        ] {
            let mut request = evidence_content_request(artifact, access.unwrap_or(""));
            if access.is_none() {
                request.headers_mut().remove(EVIDENCE_ACCESS_REQUEST_HEADER);
            }
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let error: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap())
                    .unwrap();
            assert_eq!(error["error_code"], expected);
        }

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let unavailable = Fixture::with_decision_catalog(
            PostgresIdentityStore::from_pool(pool),
            "operator-1",
            ManagementRole::SensitiveEvidenceReader,
        );
        let response = router(unavailable.control)
            .oneshot(evidence_content_request(MISSING_ARTIFACT_ID, access_id))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(
            error["error_code"],
            "CONTROL_EVIDENCE_READ_STORE_UNAVAILABLE"
        );
        assert_access_event_targets_and_evidence(
            &unavailable.access_directory,
            "evidence.read",
            &[None],
            &[Some(MISSING_ARTIFACT_ID)],
            &[None],
            &[Some(access_id)],
            &[0],
        );
    }

    #[tokio::test]
    async fn evidence_access_decision_enforces_role_input_and_store_availability() {
        let invalid = Fixture::new(10, ManagementRole::SensitiveEvidenceApprover);
        let response = router(invalid.control)
            .oneshot(evidence_access_decision_request(
                "not-an-access-request",
                "approve",
                "evidence-decision-key-0001",
                r#"{"reason":"Approve review","ttl_seconds":300}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_access_events(
            &invalid.access_directory,
            1,
            "evidence.access.approved",
            None,
        );

        let unknown = Fixture::new(10, ManagementRole::SensitiveEvidenceApprover);
        let response = router(unknown.control)
            .oneshot(evidence_access_decision_request(
                "access_018f2a3b-4c5d-7000-8000-000000000970",
                "approve",
                "evidence-decision-key-0002",
                r#"{"reason":"Approve review","ttl_seconds":300,"scope":"untrusted"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let forbidden = Fixture::new(10, ManagementRole::Investigator);
        let response = router(forbidden.control)
            .oneshot(evidence_access_decision_request(
                "access_018f2a3b-4c5d-7000-8000-000000000970",
                "deny",
                "evidence-decision-key-0003",
                r#"{"reason":"Reject review"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        let unavailable = Fixture::with_decision_catalog(
            PostgresIdentityStore::from_pool(pool),
            "approver-1",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let access_request_id = "access_018f2a3b-4c5d-7000-8000-000000000970";
        let response = router(unavailable.control)
            .oneshot(evidence_access_decision_request(
                access_request_id,
                "approve",
                "evidence-decision-key-0004",
                r#"{"reason":"Approve review","ttl_seconds":300}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["error_code"],
            "CONTROL_EVIDENCE_ACCESS_DECISION_STORE_UNAVAILABLE"
        );
        assert_access_event_targets_and_evidence(
            &unavailable.access_directory,
            "evidence.access.approved",
            &[None],
            &[None],
            &[None],
            &[Some(access_request_id)],
            &[0],
        );
    }

    #[tokio::test]
    #[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn evidence_access_request_is_idempotent_bounded_and_audited() {
        let database_url =
            std::env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
        let catalog = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
            .await
            .expect("evidence access store connects");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("assertion pool connects");
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let case_id = "case_018f2a3b-4c5d-7000-8000-000000000981";
        sqlx::query(
            "INSERT INTO xshield.investigation_cases (
                tenant_id, site_id, case_id, owner_ref, purpose, status,
                idempotency_digest, request_digest, created_event_id
             ) VALUES (
                'tenant_a', 'site_a', $1, 'operator-1', 'Investigate evidence', 'open',
                decode(repeat('31', 32), 'hex'), decode(repeat('32', 32), 'hex'),
                'ev_018f2a3b-4c5d-7000-8000-000000000982'
             )",
        )
        .bind(case_id)
        .execute(&pool)
        .await
        .unwrap();
        let root = std::env::temp_dir().join(format!(
            "xshield-control-access-evidence-{}",
            Uuid::now_v7()
        ));
        private_directory(&root);
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-control", 1024, 30).unwrap(),
            EvidenceKey::from_hex(
                "5555555555555555555555555555555555555555555555555555555555555555",
            )
            .unwrap(),
        )
        .unwrap();
        let source_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000983").unwrap();
        let artifact_id =
            publish_test_artifact(&catalog, &vault, &tenant, &site, &source_request, 1).await;

        let fixture = Fixture::with_case_catalog(catalog.clone(), 10);
        let app = router(fixture.control);
        let body = format!(
            r#"{{"case_id":"{case_id}","access_kind":"sensitive_raw","justification":"Verify the source response"}}"#
        );
        let first = app
            .clone()
            .oneshot(evidence_access_request_owned(
                &artifact_id,
                "evidence-access-key-1001",
                body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first: Value =
            serde_json::from_slice(&to_bytes(first.into_body(), 16 * 1024).await.unwrap()).unwrap();
        let access_request_id = first["access_request_id"].as_str().unwrap().to_owned();
        assert_eq!(first["status"], "pending");
        assert_eq!(first["replayed"], false);

        let retry = app
            .clone()
            .oneshot(evidence_access_request_owned(
                &artifact_id,
                "evidence-access-key-1001",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        let retry: Value =
            serde_json::from_slice(&to_bytes(retry.into_body(), 16 * 1024).await.unwrap()).unwrap();
        assert_eq!(retry["access_request_id"], access_request_id);
        assert_eq!(retry["replayed"], true);

        let conflict = app
            .clone()
            .oneshot(evidence_access_request(
                &artifact_id,
                "evidence-access-key-1001",
                &format!(
                    r#"{{"case_id":"{case_id}","access_kind":"sensitive_raw","justification":"Different reason"}}"#
                ),
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        let capacity = app
            .clone()
            .oneshot(evidence_access_request(
                &artifact_id,
                "evidence-access-key-1002",
                &format!(
                    r#"{{"case_id":"{case_id}","access_kind":"sensitive_raw","justification":"Second request"}}"#
                ),
            ))
            .await
            .unwrap();
        assert_eq!(capacity.status(), StatusCode::TOO_MANY_REQUESTS);
        let missing = app
            .oneshot(evidence_access_request(
                MISSING_ARTIFACT_ID,
                "evidence-access-key-1003",
                &format!(
                    r#"{{"case_id":"{case_id}","access_kind":"sensitive_raw","justification":"Missing evidence"}}"#
                ),
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let approver_fixture = Fixture::with_decision_catalog(
            catalog.clone(),
            "approver-1",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let approved = router(approver_fixture.control)
            .oneshot(evidence_access_decision_request(
                &access_request_id,
                "approve",
                "evidence-content-decision-1001",
                r#"{"reason":"Read source response","ttl_seconds":600}"#,
            ))
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);
        let reader_fixture = Fixture::with_decision_catalog(
            catalog,
            "operator-1",
            ManagementRole::SensitiveEvidenceReader,
        )
        .with_evidence_read_port(EvidenceReadPort::new(vault));
        let reader_app = router(reader_fixture.control);
        let content = reader_app
            .clone()
            .oneshot(evidence_content_request(&artifact_id, &access_request_id))
            .await
            .unwrap();
        assert_eq!(content.status(), StatusCode::OK);
        assert_eq!(content.headers()[CONTENT_TYPE], "application/octet-stream");
        assert_eq!(content.headers()["cache-control"], "private, no-store");
        assert_eq!(content.headers()["x-content-type-options"], "nosniff");
        assert_eq!(content.headers()["x-xshield-tenant-id"], "tenant_a");
        assert_eq!(content.headers()["x-xshield-site-id"], "site_a");
        assert_eq!(content.headers()["x-xshield-artifact-id"], artifact_id);
        assert_eq!(
            content.headers()[EVIDENCE_ACCESS_REQUEST_HEADER],
            access_request_id
        );
        assert!(
            RequestId::parse(content.headers()["x-xshield-request-id"].to_str().unwrap()).is_ok()
        );
        assert_eq!(content.headers()["content-length"], "17");
        assert_eq!(
            content.headers()[CONTENT_DISPOSITION],
            "attachment; filename=\"evidence.bin\""
        );
        let saturated = reader_app
            .clone()
            .oneshot(evidence_content_request(&artifact_id, &access_request_id))
            .await
            .unwrap();
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error: Value =
            serde_json::from_slice(&to_bytes(saturated.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(
            error["error_code"],
            "CONTROL_EVIDENCE_READ_CAPACITY_EXHAUSTED"
        );
        let content = to_bytes(content.into_body(), 1024).await.unwrap();
        assert_eq!(&content[..], br#"{"approved":true}"#);
        drop(content);
        let retry = reader_app
            .clone()
            .oneshot(evidence_content_request(&artifact_id, &access_request_id))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        drop(retry);

        let object = root.join(format!("{artifact_id}.xev"));
        let ciphertext = fs::read(&object).unwrap();
        fs::write(&object, b"corrupt").unwrap();
        let corrupt = reader_app
            .clone()
            .oneshot(evidence_content_request(&artifact_id, &access_request_id))
            .await
            .unwrap();
        assert_eq!(corrupt.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error: Value =
            serde_json::from_slice(&to_bytes(corrupt.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(error["error_code"], "CONTROL_EVIDENCE_READ_CORRUPT");
        fs::write(&object, ciphertext).unwrap();
        let recovered = reader_app
            .oneshot(evidence_content_request(&artifact_id, &access_request_id))
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
        drop(recovered);
        assert_access_event_targets_and_evidence(
            &reader_fixture.access_directory,
            "evidence.read",
            &[None; 5],
            &[Some(artifact_id.as_str()); 5],
            &[None; 5],
            &[Some(access_request_id.as_str()); 5],
            &[1, 0, 1, 0, 1],
        );

        let envelope: Value = sqlx::query_scalar(
            "SELECT envelope FROM xshield.audit_outbox
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND aggregate_ref = $1 AND event_type = 'evidence.access.requested'",
        )
        .bind(&access_request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(envelope["payload"]["case_id"], case_id);
        assert_eq!(envelope["payload"]["artifact_id"], artifact_id);
        assert_eq!(envelope["payload"]["subject_ref"], "operator-1");
        assert!(!envelope.to_string().contains("evidence-access-key"));
        assert_evidence_access_events(
            &fixture.access_directory,
            &[
                Some(artifact_id.as_str()),
                Some(artifact_id.as_str()),
                Some(artifact_id.as_str()),
                Some(artifact_id.as_str()),
                Some(MISSING_ARTIFACT_ID),
            ],
            &[
                Some(case_id),
                Some(case_id),
                Some(case_id),
                Some(case_id),
                Some(case_id),
            ],
            &[
                Some(access_request_id.as_str()),
                Some(access_request_id.as_str()),
                None,
                None,
                None,
            ],
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
    #[allow(clippy::too_many_lines)]
    async fn evidence_access_decision_is_independent_short_lived_and_audited() {
        let database_url =
            std::env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
        let catalog = PostgresIdentityStore::connect(&database_url, 4, Duration::from_secs(5))
            .await
            .expect("evidence decision store connects");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("assertion pool connects");
        seed_control_decision_targets(&pool).await;
        let approve_id = "access_018f2a3b-4c5d-7000-8000-000000000972";
        let case_id = "case_018f2a3b-4c5d-7000-8000-000000000970";
        let artifact_id = "artifact_018f2a3b-4c5d-7000-8000-000000000971";
        let approve_body = r#"{"reason":"Approved incident verification","ttl_seconds":600}"#;

        let approved_fixture = Fixture::with_decision_catalog(
            catalog.clone(),
            "approver-1",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let approved = router(approved_fixture.control)
            .oneshot(evidence_access_decision_request(
                approve_id,
                "approve",
                "evidence-decision-key-1001",
                approve_body,
            ))
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::OK);
        assert_eq!(approved.headers()["cache-control"], "private, no-store");
        let approved: Value =
            serde_json::from_slice(&to_bytes(approved.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(approved["status"], "approved");
        assert_eq!(approved["requested_by"], "operator-1");
        assert_eq!(approved["decided_by"], "approver-1");
        assert!(approved["access_expires_at"].is_string());
        assert_eq!(approved["replayed"], false);
        assert_access_event_targets_and_evidence(
            &approved_fixture.access_directory,
            "evidence.access.approved",
            &[None],
            &[Some(artifact_id)],
            &[Some(case_id)],
            &[Some(approve_id)],
            &[1],
        );

        sqlx::query(
            "UPDATE xshield.artifact_catalog
             SET status = 'deleted', deleted_at = clock_timestamp()
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a' AND artifact_id = $1",
        )
        .bind(artifact_id)
        .execute(&pool)
        .await
        .unwrap();
        let replay_fixture = Fixture::with_decision_catalog(
            catalog.clone(),
            "approver-1",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let replay = router(replay_fixture.control)
            .oneshot(evidence_access_decision_request(
                approve_id,
                "approve",
                "evidence-decision-key-1001",
                approve_body,
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        let replay: Value =
            serde_json::from_slice(&to_bytes(replay.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["access_request_id"], approve_id);

        let conflict_fixture = Fixture::with_decision_catalog(
            catalog.clone(),
            "approver-1",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let conflict = router(conflict_fixture.control)
            .oneshot(evidence_access_decision_request(
                approve_id,
                "approve",
                "evidence-decision-key-1001",
                r#"{"reason":"Approved incident verification","ttl_seconds":300}"#,
            ))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let self_fixture = Fixture::with_decision_catalog(
            catalog.clone(),
            "operator-1",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let self_approval = router(self_fixture.control)
            .oneshot(evidence_access_decision_request(
                "access_018f2a3b-4c5d-7000-8000-000000000973",
                "approve",
                "evidence-decision-key-1002",
                r#"{"reason":"Self approval","ttl_seconds":300}"#,
            ))
            .await
            .unwrap();
        assert_eq!(self_approval.status(), StatusCode::FORBIDDEN);

        let denied_fixture = Fixture::with_decision_catalog(
            catalog.clone(),
            "approver-2",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let denied = router(denied_fixture.control)
            .oneshot(evidence_access_decision_request(
                "access_018f2a3b-4c5d-7000-8000-000000000974",
                "deny",
                "evidence-decision-key-1003",
                r#"{"reason":"Insufficient justification"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::OK);
        let denied: Value =
            serde_json::from_slice(&to_bytes(denied.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(denied["status"], "denied");
        assert!(denied["access_expires_at"].is_null());

        let stale_fixture = Fixture::with_decision_catalog(
            catalog,
            "approver-3",
            ManagementRole::SensitiveEvidenceApprover,
        );
        let stale = router(stale_fixture.control)
            .oneshot(evidence_access_decision_request(
                "access_018f2a3b-4c5d-7000-8000-000000000975",
                "approve",
                "evidence-decision-key-1004",
                r#"{"reason":"Stale target","ttl_seconds":300}"#,
            ))
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::NOT_FOUND);

        let envelope: Value = sqlx::query_scalar(
            "SELECT envelope FROM xshield.audit_outbox
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND aggregate_ref = $1 AND event_type = 'evidence.access.approved'",
        )
        .bind(approve_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let envelope_text = envelope.to_string();
        assert_eq!(envelope["payload"]["subject_ref"], "approver-1");
        assert_eq!(envelope["payload"]["decision"], "approved");
        assert!(!envelope_text.contains("evidence-decision-key"));
        assert!(!envelope_text.contains("Approved incident verification"));
        cleanup_control_decision_targets(&pool).await;
    }

    async fn seed_control_decision_targets(pool: &sqlx::PgPool) {
        cleanup_control_decision_targets(pool).await;
        sqlx::query(
            "INSERT INTO xshield.investigation_cases (
                tenant_id, site_id, case_id, owner_ref, purpose, status,
                idempotency_digest, request_digest, created_event_id
             ) VALUES (
                'tenant_a', 'site_a',
                'case_018f2a3b-4c5d-7000-8000-000000000970',
                'operator-1', 'Decision control test', 'open',
                decode(repeat('41', 32), 'hex'), decode(repeat('42', 32), 'hex'),
                'ev_018f2a3b-4c5d-7000-8000-000000000969'
             )",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO xshield.artifact_catalog (
                tenant_id, site_id, artifact_id, request_id, schema_version, kind,
                content_type, capture_status, fidelity, bytes_observed, bytes_saved,
                classification, example_only, storage_profile, storage_locator,
                key_ref, integrity_algorithm, integrity_digest, parent_refs,
                recorded_at, expires_at, catalog_event_id, status, deleted_at
             ) VALUES (
                'tenant_a', 'site_a',
                'artifact_018f2a3b-4c5d-7000-8000-000000000971',
                'req_018f2a3b-4c5d-7000-8000-000000000968', 3,
                'response_from_origin', 'application/json', 'complete', 'entity_exact', 2, 2,
                'RESTRICTED', false, 'aead_envelope_v1',
                'artifact_018f2a3b-4c5d-7000-8000-000000000971.xev',
                'evidence-key-r1', 'sha256_ciphertext', repeat('c', 64), '{}',
                clock_timestamp(), clock_timestamp() + interval '20 minutes',
                'ev_018f2a3b-4c5d-7000-8000-000000000967', 'active', NULL
             )",
        )
        .execute(pool)
        .await
        .unwrap();
        for suffix in [
            "000000000972",
            "000000000973",
            "000000000974",
            "000000000975",
        ] {
            sqlx::query(
                "INSERT INTO xshield.evidence_access_requests (
                    tenant_id, site_id, access_request_id, case_id, artifact_id,
                    requested_by, access_kind, justification, status,
                    idempotency_digest, request_digest, requested_event_id
                 ) VALUES (
                    'tenant_a', 'site_a', $1,
                    'case_018f2a3b-4c5d-7000-8000-000000000970',
                    'artifact_018f2a3b-4c5d-7000-8000-000000000971',
                    'operator-1', 'sensitive_raw', 'Decision fixture', 'pending',
                    decode(md5($1) || md5($1), 'hex'),
                    decode(md5($1 || 'request') || md5($1 || 'request'), 'hex'),
                    'ev_018f2a3b-4c5d-7000-8000-' || right($1, 12)
                 )",
            )
            .bind(format!("access_018f2a3b-4c5d-7000-8000-{suffix}"))
            .execute(pool)
            .await
            .unwrap();
        }
    }

    async fn cleanup_control_decision_targets(pool: &sqlx::PgPool) {
        sqlx::query(
            "DELETE FROM xshield.evidence_access_requests
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND access_request_id >= 'access_018f2a3b-4c5d-7000-8000-000000000972'
               AND access_request_id <= 'access_018f2a3b-4c5d-7000-8000-000000000975'",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM xshield.artifact_catalog
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND artifact_id = 'artifact_018f2a3b-4c5d-7000-8000-000000000971'",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM xshield.investigation_cases
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND case_id = 'case_018f2a3b-4c5d-7000-8000-000000000970'",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "DELETE FROM xshield.audit_outbox
             WHERE tenant_id = 'tenant_a' AND site_id = 'site_a'
               AND aggregate_ref >= 'access_018f2a3b-4c5d-7000-8000-000000000972'
               AND aggregate_ref <= 'access_018f2a3b-4c5d-7000-8000-000000000975'",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
    async fn evidence_manifests_are_scoped_paginated_and_audited() {
        let database_url =
            std::env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
        let catalog = PostgresIdentityStore::connect(&database_url, 3, Duration::from_secs(5))
            .await
            .expect("catalog connects");
        let fixture = Fixture::with_catalog(10, ManagementRole::Observer, catalog.clone(), 1);
        let root =
            std::env::temp_dir().join(format!("xshield-control-evidence-{}", Uuid::now_v7()));
        private_directory(&root);
        let vault = LocalEvidenceVault::open(
            EvidenceVaultConfig::new(&root, "evidence-key-control", 1024, 30).unwrap(),
            EvidenceKey::from_hex(
                "4444444444444444444444444444444444444444444444444444444444444444",
            )
            .unwrap(),
        )
        .unwrap();
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000111").unwrap();
        let first = publish_test_artifact(&catalog, &vault, &tenant, &site, &request, 1).await;
        let second = publish_test_artifact(&catalog, &vault, &tenant, &site, &request, 2).await;

        let path = format!("/control/v1/requests/{}/evidence", request.as_str());
        let app = router(fixture.control);
        let first_page = app
            .clone()
            .oneshot(authenticated_path(&path))
            .await
            .unwrap();
        assert_eq!(first_page.status(), StatusCode::OK);
        assert_eq!(first_page.headers()["cache-control"], "private, no-store");
        let body = to_bytes(first_page.into_body(), 32 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["tenant_id"], tenant.as_str());
        assert_eq!(body["site_id"], site.as_str());
        assert_eq!(body["artifacts"].as_array().unwrap().len(), 1);
        assert_eq!(body["truncated"], true);
        let returned = body["artifacts"][0]["artifact_id"].as_str().unwrap();
        assert!(returned == first || returned == second);
        assert!(body["artifacts"][0].get("plaintext").is_none());
        let cursor = body["next_cursor"].as_str().unwrap();

        let other_request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000112").unwrap();
        let wrong_scope = app
            .clone()
            .oneshot(authenticated_path(&format!(
                "/control/v1/requests/{}/evidence?cursor={cursor}",
                other_request.as_str()
            )))
            .await
            .unwrap();
        assert_eq!(wrong_scope.status(), StatusCode::BAD_REQUEST);

        let second_page = app
            .clone()
            .oneshot(authenticated_path(&format!("{path}?cursor={cursor}")))
            .await
            .unwrap();
        assert_eq!(second_page.status(), StatusCode::OK);
        let body = to_bytes(second_page.into_body(), 32 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["artifacts"].as_array().unwrap().len(), 1);
        assert_ne!(body["artifacts"][0]["artifact_id"], returned);
        assert_eq!(body["truncated"], false);
        assert!(body["next_cursor"].is_null());

        assert_artifact_endpoints(&app, &first).await;
        assert_access_event_targets_and_evidence(
            &fixture.access_directory,
            "console.manifest.read",
            &[
                Some(request.as_str()),
                Some(other_request.as_str()),
                Some(request.as_str()),
                None,
                None,
            ],
            &[
                None,
                None,
                None,
                Some(first.as_str()),
                Some(MISSING_ARTIFACT_ID),
            ],
            &[None, None, None, None, None],
            &[None, None, None, None, None],
            &[1, 0, 1, 1, 0],
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn authenticated_path(path: &str) -> Request<Body> {
        Request::get(path)
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap()
    }

    fn case_request(idempotency_key: &str, body: &'static str) -> Request<Body> {
        Request::post(super::CASES_PATH)
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .body(Body::from(body))
            .unwrap()
    }

    fn evidence_access_request(
        artifact_id: &str,
        idempotency_key: &str,
        body: &str,
    ) -> Request<Body> {
        evidence_access_request_owned(artifact_id, idempotency_key, body.to_owned())
    }

    fn evidence_access_request_owned(
        artifact_id: &str,
        idempotency_key: &str,
        body: String,
    ) -> Request<Body> {
        Request::post(format!("/control/v1/artifacts/{artifact_id}/access"))
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .header("idempotency-key", idempotency_key)
            .body(Body::from(body))
            .unwrap()
    }

    fn evidence_access_decision_request(
        access_request_id: &str,
        decision: &str,
        idempotency_key: &str,
        body: &str,
    ) -> Request<Body> {
        Request::post(format!(
            "/control/v1/evidence-access-requests/{access_request_id}/{decision}"
        ))
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .header("idempotency-key", idempotency_key)
        .body(Body::from(body.to_owned()))
        .unwrap()
    }

    fn evidence_content_request(artifact_id: &str, access_request_id: &str) -> Request<Body> {
        Request::get(format!("/control/v1/artifacts/{artifact_id}/content"))
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(EVIDENCE_ACCESS_REQUEST_HEADER, access_request_id)
            .body(Body::empty())
            .unwrap()
    }

    async fn assert_artifact_endpoints(app: &axum::Router, artifact_id: &str) {
        let artifact = app
            .clone()
            .oneshot(authenticated_path(&format!(
                "/control/v1/artifacts/{artifact_id}"
            )))
            .await
            .unwrap();
        assert_eq!(artifact.status(), StatusCode::OK);
        assert_eq!(artifact.headers()["cache-control"], "private, no-store");
        let body = to_bytes(artifact.into_body(), 32 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["source_artifact_id"], artifact_id);
        assert_eq!(body["found"], true);
        assert_eq!(body["artifact"]["artifact_id"], artifact_id);
        assert!(body["artifact"].get("plaintext").is_none());

        let missing = app
            .clone()
            .oneshot(authenticated_path(&format!(
                "/control/v1/artifacts/{MISSING_ARTIFACT_ID}"
            )))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::OK);
        let body = to_bytes(missing.into_body(), 32 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["source_artifact_id"], MISSING_ARTIFACT_ID);
        assert_eq!(body["found"], false);
        assert!(body["artifact"].is_null());
    }

    async fn publish_test_artifact(
        catalog: &PostgresIdentityStore,
        vault: &LocalEvidenceVault,
        tenant: &TenantId,
        site: &SiteId,
        request: &RequestId,
        sequence: u64,
    ) -> String {
        let verified = vault
            .write(&EvidenceWrite {
                tenant_id: tenant,
                site_id: site,
                request_id: request,
                kind: "request_decoded",
                content_type: "application/json",
                fidelity: EvidenceFidelity::EntityExact,
                classification: EvidenceClassification::Restricted,
                parent_refs: &[],
                expires_at: Utc::now() + chrono::TimeDelta::minutes(10),
                plaintext: br#"{"approved":true}"#,
            })
            .unwrap();
        let artifact_id = verified.manifest().artifact_id.clone();
        let event = EventId::parse(format!("ev_{}", Uuid::now_v7())).unwrap();
        let trace_id = Uuid::now_v7().simple().to_string();
        let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let envelope = json!({
            "schema_version": 3,
            "event_id": event.as_str(),
            "event_type": "evidence.cataloged",
            "tenant_id": tenant.as_str(),
            "site_id": site.as_str(),
            "request_id": request.as_str(),
            "trace_id": trace_id,
            "span_id": &trace_id[..16],
            "producer_id": "xshield-control-test",
            "producer_boot_id": "control-test",
            "producer_seq": sequence,
            "request_seq": sequence,
            "occurred_at": occurred_at,
            "observed_at": occurred_at,
            "policy_revision": "policy-test-r1",
            "example_only": false,
            "evidence_refs": [artifact_id],
            "cause_event_ids": [],
            "payload": {
                "stage": "evidence_catalog",
                "outcome": "PASS",
                "reason_code": "EVIDENCE_CATALOG_PUBLISHED",
                "artifact_id": artifact_id
            },
            "sensitivity": "RESTRICTED",
            "integrity": {"state": "pending", "previous_hash": null, "event_hash": null}
        });
        assert_eq!(
            catalog
                .publish_evidence_manifest(
                    EvidenceCatalogPublish::new(&verified, &event, &envelope).unwrap()
                )
                .await
                .unwrap(),
            EvidenceCatalogWriteOutcome::Published
        );
        artifact_id
    }

    fn authenticated_request() -> Request<Body> {
        Request::get(super::HEALTH_PATH)
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap()
    }

    fn event_summary(event_id: &str, request_seq: u32) -> AuditEventSummary {
        AuditEventSummary {
            event_id: event_id.to_owned(),
            event_type: "stage.completed".to_owned(),
            stage: "admission".to_owned(),
            outcome: "PASS".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            proof_kind: "deterministic".to_owned(),
            confidence: None,
            confidence_status: "not_applicable".to_owned(),
            occurred_at: Utc::now(),
            request_seq,
            duration_us: 10,
            policy_revision: "policy-r1".to_owned(),
            model_revision: String::new(),
            evidence_refs: Vec::new(),
            cause_event_ids: Vec::new(),
            sensitivity: "INTERNAL".to_owned(),
        }
    }

    #[derive(Clone, Debug, Row, Serialize)]
    struct SummaryRow {
        event_count: u64,
        #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
        first_occurred_at: DateTime<Utc>,
        #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
        last_occurred_at: DateTime<Utc>,
        method: String,
        operation_id: String,
        decision: String,
        reason_code: String,
        status: Option<u16>,
        origin_state: String,
        duration_us: u64,
        forwarded: u8,
        terminal: u8,
    }

    #[derive(Clone, Debug, Row, Serialize)]
    struct ModelRow {
        event_id: String,
        event_type: String,
        request_id: String,
        #[serde(with = "clickhouse::serde::chrono::datetime64::micros")]
        occurred_at: DateTime<Utc>,
        request_seq: u32,
        evidence_refs: Vec<String>,
        cause_event_ids: Vec<String>,
        sensitivity: String,
        payload_json: String,
    }

    struct Fixture {
        control: ControlPlane,
        access_directory: std::path::PathBuf,
    }

    impl Fixture {
        fn new(rate_limit: u64, role: ManagementRole) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Self::with_window(rate_limit, role, now - 1, now + 3600)
        }

        fn with_index(rate_limit: u64, role: ManagementRole, index: Client) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Self::with_window_and_index(rate_limit, role, now - 1, now + 3600, index)
        }

        fn with_catalog(
            rate_limit: u64,
            role: ManagementRole,
            catalog: PostgresIdentityStore,
            max_query_artifacts: u16,
        ) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Self::with_dependencies(
                rate_limit,
                role,
                now - 1,
                now + 3600,
                Client::default(),
                catalog,
                max_query_artifacts,
                10_000,
            )
        }

        fn with_case_catalog(catalog: PostgresIdentityStore, max_open_cases: u32) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Self::with_dependencies(
                10,
                ManagementRole::Investigator,
                now - 1,
                now + 3600,
                Client::default(),
                catalog,
                1,
                max_open_cases,
            )
        }

        fn with_decision_catalog(
            catalog: PostgresIdentityStore,
            subject: &str,
            role: ManagementRole,
        ) -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Self::with_subject_dependencies(
                10,
                subject,
                role,
                now - 1,
                now + 3600,
                Client::default(),
                catalog,
                1,
                10_000,
            )
        }

        fn with_window(
            rate_limit: u64,
            role: ManagementRole,
            token_issued_at: u64,
            token_expires_at: u64,
        ) -> Self {
            Self::with_window_and_index(
                rate_limit,
                role,
                token_issued_at,
                token_expires_at,
                Client::default(),
            )
        }

        fn with_window_and_index(
            rate_limit: u64,
            role: ManagementRole,
            token_issued_at: u64,
            token_expires_at: u64,
            index: Client,
        ) -> Self {
            Self::with_dependencies(
                rate_limit,
                role,
                token_issued_at,
                token_expires_at,
                index,
                lazy_catalog(),
                1,
                10_000,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn with_dependencies(
            rate_limit: u64,
            role: ManagementRole,
            token_issued_at: u64,
            token_expires_at: u64,
            index: Client,
            catalog: PostgresIdentityStore,
            max_query_artifacts: u16,
            max_open_cases: u32,
        ) -> Self {
            Self::with_subject_dependencies(
                rate_limit,
                "operator-1",
                role,
                token_issued_at,
                token_expires_at,
                index,
                catalog,
                max_query_artifacts,
                max_open_cases,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn with_subject_dependencies(
            rate_limit: u64,
            subject: &str,
            role: ManagementRole,
            token_issued_at: u64,
            token_expires_at: u64,
            index: Client,
            catalog: PostgresIdentityStore,
            max_query_artifacts: u16,
            max_open_cases: u32,
        ) -> Self {
            let root =
                std::env::temp_dir().join(format!("xshield-control-test-{}", Uuid::now_v7()));
            let source = root.join("source");
            let manifests = root.join("manifests");
            let checkpoints = root.join("checkpoints");
            let access = root.join("access");
            private_directory(&source);
            private_directory(&manifests);
            private_directory(&access);
            let limits = JournalLimits::new(1024 * 1024, 512 * 1024, 1024 * 1024).unwrap();
            let (source_writer, _) = LocalJournal::open(
                &source,
                "journal-key-r1",
                JournalKey::from_hex(JOURNAL_KEY).unwrap(),
                limits,
            )
            .unwrap();
            drop(source_writer);
            let access_limits = JournalLimits::new(1024 * 1024, 512 * 1024, 1).unwrap();
            let (access_journal, _) = LocalJournal::open(
                &access,
                "control-key-r1",
                JournalKey::from_hex(JOURNAL_KEY).unwrap(),
                access_limits,
            )
            .unwrap();
            let tenant = TenantId::parse("tenant_a").unwrap();
            let site = SiteId::parse("site_a").unwrap();
            let principal =
                ManagementPrincipal::new(subject, [role], [(tenant.clone(), site.clone())])
                    .unwrap();
            let publisher = PublisherConfig::new(
                source,
                manifests,
                checkpoints,
                "clickhouse-primary",
                "audit_events",
                30,
                1024 * 1024,
            )
            .unwrap();
            let credential =
                ManagementCredential::new(TOKEN, token_issued_at, token_expires_at).unwrap();
            let config = ControlConfig::new(
                credential,
                CursorKey::from_hex(CURSOR_KEY).unwrap(),
                IdempotencyKey::from_hex(IDEMPOTENCY_KEY).unwrap(),
                principal,
                tenant,
                site,
                publisher,
                "journal-key-r1",
                ControlLimits::new(rate_limit, 1, max_query_artifacts, max_open_cases, 1, 900)
                    .unwrap(),
            )
            .unwrap();
            let seal_key = test_seal_key();
            Self {
                control: ControlPlane::new(
                    config,
                    JournalKey::from_hex(JOURNAL_KEY).unwrap(),
                    seal_key,
                    index,
                    catalog,
                    access_journal,
                ),
                access_directory: access,
            }
        }

        fn with_evidence_read_port(mut self, port: EvidenceReadPort) -> Self {
            self.control = self.control.with_evidence_read_port(port);
            self
        }
    }

    fn test_seal_key() -> SealVerifyingKey {
        let signing = SealSigningKey::from_hex("seal-key-r1", SEAL_KEY).unwrap();
        signing.verifying_key().unwrap()
    }

    fn lazy_catalog() -> PostgresIdentityStore {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        PostgresIdentityStore::from_pool(pool)
    }

    fn assert_access_events(
        directory: &Path,
        expected: usize,
        event_type: &str,
        target_request_id: Option<&str>,
    ) {
        assert_access_event_targets(directory, event_type, &vec![target_request_id; expected]);
    }

    fn assert_access_event_targets(
        directory: &Path,
        event_type: &str,
        target_request_ids: &[Option<&str>],
    ) {
        assert_access_event_targets_and_evidence(
            directory,
            event_type,
            target_request_ids,
            &vec![None; target_request_ids.len()],
            &vec![None; target_request_ids.len()],
            &vec![None; target_request_ids.len()],
            &vec![0; target_request_ids.len()],
        );
    }

    fn assert_case_access_events(directory: &Path, target_case_ids: &[Option<&str>]) {
        assert_access_event_targets_and_evidence(
            directory,
            "case.created",
            &vec![None; target_case_ids.len()],
            &vec![None; target_case_ids.len()],
            target_case_ids,
            &vec![None; target_case_ids.len()],
            &vec![0; target_case_ids.len()],
        );
    }

    fn assert_evidence_access_events(
        directory: &Path,
        target_artifact_ids: &[Option<&str>],
        target_case_ids: &[Option<&str>],
        target_access_request_ids: &[Option<&str>],
    ) {
        let evidence_counts = target_access_request_ids
            .iter()
            .map(|target| usize::from(target.is_some()))
            .collect::<Vec<_>>();
        assert_access_event_targets_and_evidence(
            directory,
            "evidence.access.requested",
            &vec![None; target_access_request_ids.len()],
            target_artifact_ids,
            target_case_ids,
            target_access_request_ids,
            &evidence_counts,
        );
    }

    fn assert_access_event_targets_and_evidence(
        directory: &Path,
        event_type: &str,
        target_request_ids: &[Option<&str>],
        target_artifact_ids: &[Option<&str>],
        target_case_ids: &[Option<&str>],
        target_access_request_ids: &[Option<&str>],
        evidence_counts: &[usize],
    ) {
        assert_eq!(target_request_ids.len(), evidence_counts.len());
        assert_eq!(target_artifact_ids.len(), evidence_counts.len());
        assert_eq!(target_case_ids.len(), evidence_counts.len());
        assert_eq!(target_access_request_ids.len(), evidence_counts.len());
        let events = read_access_events(directory);
        assert_eq!(events.len(), target_request_ids.len());
        for (
            (
                (((event, target_request_id), target_artifact_id), target_case_id),
                target_access_request_id,
            ),
            evidence_count,
        ) in events
            .into_iter()
            .zip(target_request_ids)
            .zip(target_artifact_ids)
            .zip(target_case_ids)
            .zip(target_access_request_ids)
            .zip(evidence_counts)
        {
            assert_eq!(event["event_type"], event_type);
            assert_eq!(
                event["payload"]["method"],
                if matches!(
                    event_type,
                    "case.created"
                        | "evidence.access.requested"
                        | "evidence.access.approved"
                        | "evidence.access.denied"
                        | "console.query.executed"
                ) {
                    "POST"
                } else {
                    "GET"
                }
            );
            assert_eq!(
                event["evidence_refs"].as_array().unwrap().len(),
                *evidence_count
            );
            assert!(event["payload"]["reason_code"].is_string());
            if event_type == "evidence.read" {
                if *evidence_count == 1 {
                    assert_eq!(
                        event["payload"]["bytes_read"],
                        br#"{"approved":true}"#.len()
                    );
                } else {
                    assert!(event["payload"].get("bytes_read").is_none());
                }
            }
            assert_eq!(
                event["payload"]["target_request_id"],
                target_request_id.map_or(Value::Null, Value::from)
            );
            assert_eq!(
                event["payload"]["target_artifact_id"],
                target_artifact_id.map_or(Value::Null, Value::from)
            );
            assert_eq!(
                event["payload"]["target_case_id"],
                target_case_id.map_or(Value::Null, Value::from)
            );
            assert_eq!(
                event["payload"]["target_access_request_id"],
                target_access_request_id.map_or(Value::Null, Value::from)
            );
        }
    }

    fn read_access_events(directory: &Path) -> Vec<Value> {
        let manifests = directory.parent().unwrap().join("access-manifests");
        private_directory(&manifests);
        let signing = SealSigningKey::from_hex("seal-key-r1", SEAL_KEY).unwrap();
        let segments = seal_closed_segments(
            directory,
            &manifests,
            "control-key-r1",
            &JournalKey::from_hex(JOURNAL_KEY).unwrap(),
            &signing,
        )
        .unwrap();
        let verifier = signing.verifying_key().unwrap();
        segments
            .into_iter()
            .map(|segment| {
                let path =
                    directory.join(format!("segment-{}.closed.xja", segment.producer_boot_id));
                let manifest =
                    fs::read(manifests.join(format!("segment-{}.xjs", segment.producer_boot_id)))
                        .unwrap();
                let journal_key = JournalKey::from_hex(JOURNAL_KEY).unwrap();
                let mut reader = SealedSegmentReader::open(
                    path,
                    1024 * 1024,
                    "control-key-r1",
                    &journal_key,
                    &manifest,
                    &verifier,
                )
                .unwrap();
                let record = reader.next_record().unwrap().unwrap();
                let event: Value = serde_json::from_slice(record.plaintext()).unwrap();
                assert!(reader.next_record().unwrap().is_none());
                event
            })
            .collect()
    }

    #[test]
    fn search_request_converts_only_bounded_typed_filters() {
        let request: SearchRequest = serde_json::from_value(json!({
            "schema_version": 3,
            "start": "1970-01-01T00:00:10Z",
            "end": "1970-01-01T00:01:10Z",
            "filters": [
                {"kind": "text", "field": "reason_code", "value": "UI_SOURCE_MISSING"},
                {"kind": "outcome", "value": "DENY"},
                {"kind": "confidence_at_most", "basis_points": 7500}
            ],
            "sort": "occurred_at_asc",
            "limit": 25
        }))
        .unwrap();
        let plan = request.into_plan(1000).unwrap();
        assert_eq!(plan.filters().len(), 3);
        assert_eq!(plan.limit(), 25);
        assert!(
            serde_json::from_value::<SearchRequest>(json!({
                "schema_version": 3,
                "start": "1970-01-01T00:00:10Z",
                "end": "1970-01-01T00:01:10Z",
                "filters": [{"kind": "text", "field": "stage", "value": "stage;drop"}],
                "sort": "occurred_at_asc",
                "limit": 25
            }))
            .unwrap()
            .into_plan(1000)
            .is_err()
        );
        assert!(
            serde_json::from_value::<SearchRequest>(json!({
                "schema_version": 3,
                "start": "1970-01-01T00:00:10Z",
                "end": "1970-01-01T00:01:10Z",
                "sort": "occurred_at_asc",
                "limit": 1001
            }))
            .unwrap()
            .into_plan(1000)
            .is_err()
        );
    }

    fn search_payload() -> Value {
        json!({
            "schema_version": 3,
            "start": "1970-01-01T00:00:10Z",
            "end": "1970-01-01T00:01:10Z",
            "sort": "occurred_at_asc",
            "limit": 1,
            "filters": [{"kind": "request_id", "value": "req_018f2a3b-4c5d-7000-8000-000000000001"}]
        })
    }

    fn search_http_request(payload: &Value) -> Request<Body> {
        Request::post(super::search::SEARCH_PATH)
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap()
    }

    fn analytical_http_request(model_lookup: bool) -> Request<Body> {
        if model_lookup {
            Request::get(format!("/control/v1/model-calls/{MODEL_CALL_ID}"))
                .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap()
        } else {
            search_http_request(&search_references::reference_payload())
        }
    }

    fn search_event(event_id: &str, seconds: i64) -> xshield_worker::SearchEventSummary {
        xshield_worker::SearchEventSummary {
            request_id: Some("req_018f2a3b-4c5d-7000-8000-000000000001".to_owned()),
            event_id: event_id.to_owned(),
            event_type: "stage.completed".to_owned(),
            stage: Some("admission".to_owned()),
            outcome: Some("PASS".to_owned()),
            reason_code: Some("POLICY_ALLOWED".to_owned()),
            proof_kind: Some("deterministic".to_owned()),
            confidence: None,
            confidence_status: Some("not_applicable".to_owned()),
            occurred_at: DateTime::from_timestamp(seconds, 0).unwrap(),
            request_seq: 1,
            duration_us: 10,
            policy_revision: "policy-r1".to_owned(),
            model_revision: None,
            evidence_refs: Vec::new(),
            cause_event_ids: Vec::new(),
            sensitivity: "INTERNAL".to_owned(),
        }
    }

    fn assert_search_audit(directory: &Path, reason: &str, digest: Option<&str>) {
        let events = read_access_events(directory);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["event_type"], "console.query.executed");
        assert_eq!(event["payload"]["method"], "POST");
        assert_eq!(event["payload"]["path"], super::search::SEARCH_PATH);
        assert_eq!(event["payload"]["reason_code"], reason);
        assert_eq!(
            event["payload"]["query_digest"],
            digest.map_or(Value::Null, Value::from)
        );
        assert!(event["payload"].get("filters").is_none());
        assert!(event["payload"].get("cursor").is_none());
    }

    #[tokio::test]
    async fn search_pages_have_scope_completeness_and_durable_audit() {
        let mock = test::Mock::new();
        let first_id = "ev_018f2a3b-4c5d-7000-8000-000000000001";
        let second_id = "ev_018f2a3b-4c5d-7000-8000-000000000002";
        mock.add(test::handlers::provide_with_summary(
            [search_event(first_id, 20), search_event(second_id, 30)],
            r#"{"read_rows":"42","read_bytes":"512"}"#,
        ));
        mock.add(test::handlers::provide([search_event(second_id, 30)]));
        let fixture = Fixture::with_index(
            10,
            ManagementRole::Investigator,
            Client::default().with_mock(&mock),
        );
        let mut payload = search_payload();
        let app = router(fixture.control);
        let response = app
            .clone()
            .oneshot(search_http_request(&payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "private, no-store");
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body["schema_version"], 3);
        assert_eq!(body["tenant_id"], "tenant_a");
        assert_eq!(body["site_id"], "site_a");
        assert_eq!(body["truncated"], true);
        assert_eq!(body["pending_segments"], 0);
        assert_eq!(body["has_gaps"], false);
        assert!(body["index_watermark"].is_null());
        assert!(body["as_of"].is_string());
        assert_eq!(body["scanned_rows"], 42);
        assert_eq!(body["scanned_bytes"], 512);
        assert_eq!(body["events"][0]["event_id"], first_id);
        assert_eq!(
            body["events"][0]["occurred_at"],
            "1970-01-01T00:00:20.000000Z"
        );
        assert!(body["events"][0]["confidence"].is_null());
        assert!(body["events"][0].get("payload_json").is_none());
        let digest = body["query_digest"].as_str().unwrap();
        assert!(super::parse_lower_hex_32(digest).is_some());
        assert_search_audit(
            &fixture.access_directory,
            "CONTROL_QUERY_EXECUTED",
            Some(digest),
        );
        payload["cursor"] = body["next_cursor"].clone();
        let response = app.oneshot(search_http_request(&payload)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(page["query_digest"], digest);
        assert_eq!(page["events"][0]["event_id"], second_id);
        assert_eq!(page["truncated"], false);
        assert!(page["next_cursor"].is_null());
        assert!(page["scanned_rows"].is_null());
        assert_access_events(
            &fixture.access_directory,
            2,
            "console.query.executed",
            Some("req_018f2a3b-4c5d-7000-8000-000000000001"),
        );
    }

    #[tokio::test]
    async fn search_rejects_unauthorized_or_invalid_plans_before_index_access() {
        for (role, authenticated, expected) in [
            (
                ManagementRole::Investigator,
                false,
                StatusCode::UNAUTHORIZED,
            ),
            (ManagementRole::Observer, true, StatusCode::FORBIDDEN),
        ] {
            let fixture = Fixture::new(10, role);
            let mut request = search_http_request(&search_payload());
            if !authenticated {
                request.headers_mut().remove(AUTHORIZATION);
            }
            let response = router(fixture.control).oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected);
            assert_access_events(&fixture.access_directory, 1, "console.query.executed", None);
        }
        for (field, value) in [
            ("schema_version", json!(4)),
            ("start", json!("1969-12-31T23:59:59Z")),
            ("start", json!("1970-01-01T00:00:10.1Z")),
            ("start", json!("1970-01-01T01:00:10+01:00")),
            ("end", json!("2300-01-01T00:00:01Z")),
            ("end", json!("1970-01-01T00:00:10Z")),
            ("end", json!("1970-03-01T00:00:00Z")),
            ("limit", json!(0)),
            ("limit", json!(2)),
            ("tenant_id", json!("tenant_b")),
            ("sort", json!("duration_desc")),
            (
                "filters",
                json!([{"kind":"confidence_at_most","basis_points":10001}]),
            ),
            (
                "filters",
                json!([{"kind":"text","field":"payload_json","value":"x"}]),
            ),
            (
                "filters",
                json!([{"kind":"outcome","value":"ALLOW","sql":"1=1"}]),
            ),
            (
                "filters",
                json!(vec![json!({"kind":"outcome","value":"ALLOW"}); 9]),
            ),
            (
                "filters",
                json!([{"kind":"text","field":"stage","value":"x;SELECT"}]),
            ),
        ] {
            let fixture = Fixture::new(10, ManagementRole::Investigator);
            let mut payload = search_payload();
            payload[field] = value;
            let response = router(fixture.control)
                .oneshot(search_http_request(&payload))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{payload}"
            );
            assert_search_audit(&fixture.access_directory, "CONTROL_QUERY_INVALID", None);
        }
        let fixture = Fixture::new(10, ManagementRole::Investigator);
        let mut payload = search_payload();
        payload["cursor"] = json!("x".repeat(super::search::SEARCH_BODY_BYTES_MAX));
        let response = router(fixture.control)
            .oneshot(search_http_request(&payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_search_audit(&fixture.access_directory, "CONTROL_QUERY_INVALID", None);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn search_cursor_binds_scope_credential_plan_and_microsecond_position() {
        let fixture = Fixture::new(10, ManagementRole::Investigator);
        let mut control = fixture.control;
        let payload = search_payload();
        let plan = serde_json::from_value::<SearchRequest>(payload.clone())
            .unwrap()
            .into_plan(1000)
            .unwrap();
        let position = xshield_worker::SearchPosition::new(
            DateTime::from_timestamp_micros(20_123_456).unwrap(),
            EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000001").unwrap(),
        )
        .unwrap();
        let cursor = control
            .encode_search_cursor("operator-1", &plan, &position)
            .unwrap();
        assert_eq!(
            control
                .decode_search_cursor("operator-1", &plan, &cursor)
                .unwrap(),
            position
        );
        assert!(
            control
                .decode_search_cursor("operator-2", &plan, &cursor)
                .is_err()
        );
        for (field, value) in [
            ("start", json!("1970-01-01T00:00:11Z")),
            ("end", json!("1970-01-01T00:01:11Z")),
            ("sort", json!("occurred_at_desc")),
            ("limit", json!(2)),
            ("filters", json!([])),
        ] {
            let mut different = payload.clone();
            different[field] = value;
            let different = serde_json::from_value::<SearchRequest>(different)
                .unwrap()
                .into_plan(1000)
                .unwrap();
            assert!(
                control
                    .decode_search_cursor("operator-1", &different, &cursor)
                    .is_err()
            );
        }
        control.config.tenant_id = TenantId::parse("tenant_b").unwrap();
        assert!(
            control
                .decode_search_cursor("operator-1", &plan, &cursor)
                .is_err()
        );
        control.config.tenant_id = TenantId::parse("tenant_a").unwrap();
        control.config.site_id = SiteId::parse("site_b").unwrap();
        assert!(
            control
                .decode_search_cursor("operator-1", &plan, &cursor)
                .is_err()
        );
        control.config.site_id = SiteId::parse("site_a").unwrap();
        control.config.credential.token_digest[0] ^= 1;
        assert!(
            control
                .decode_search_cursor("operator-1", &plan, &cursor)
                .is_err()
        );
        control.config.credential.token_digest[0] ^= 1;
        for seconds in [9, 70] {
            let out_of_window = xshield_worker::SearchPosition::new(
                DateTime::from_timestamp(seconds, 0).unwrap(),
                position.event_id().clone(),
            )
            .unwrap();
            let invalid = control
                .encode_search_cursor("operator-1", &plan, &out_of_window)
                .unwrap();
            assert!(
                control
                    .decode_search_cursor("operator-1", &plan, &invalid)
                    .is_err()
            );
        }
        for invalid in [
            format!("{cursor}.extra"),
            cursor.replace("20123456", "20123457"),
            "x".repeat(161),
        ] {
            assert!(
                control
                    .decode_search_cursor("operator-1", &plan, &invalid)
                    .is_err()
            );
        }
        let mut invalid_payload = payload;
        invalid_payload["cursor"] = json!("invalid");
        let response = router(control)
            .oneshot(search_http_request(&invalid_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let events = read_access_events(&fixture.access_directory);
        assert_eq!(
            events[0]["payload"]["reason_code"],
            "CONTROL_CURSOR_INVALID"
        );
        assert!(
            super::parse_lower_hex_32(events[0]["payload"]["query_digest"].as_str().unwrap())
                .is_some()
        );
    }

    #[tokio::test]
    async fn analytical_queries_distinguish_budgets_from_index_failures() {
        for code in [158, 159, 241, 209] {
            for model_lookup in [false, true] {
                let mock = test::Mock::new();
                mock.add(test::handlers::exception(code));
                let fixture = Fixture::with_index(
                    10,
                    if model_lookup {
                        ManagementRole::Observer
                    } else {
                        ManagementRole::Investigator
                    },
                    Client::default().with_mock(&mock),
                );
                let response = router(fixture.control)
                    .oneshot(analytical_http_request(model_lookup))
                    .await
                    .unwrap();
                let budget = code != 209;
                assert_eq!(
                    response.status(),
                    if budget {
                        StatusCode::TOO_MANY_REQUESTS
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                );
                let body: Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                        .unwrap();
                assert_eq!(
                    body["error_code"],
                    if budget {
                        "CONTROL_QUERY_BUDGET_EXCEEDED"
                    } else {
                        "CONTROL_INDEX_UNAVAILABLE"
                    }
                );
                assert_eq!(body["retryable"], !budget);
                assert_eq!(
                    body["next_action"],
                    if budget {
                        if model_lookup {
                            "contact_operator"
                        } else {
                            "narrow_query"
                        }
                    } else {
                        "retry_later"
                    }
                );
                let events = read_access_events(&fixture.access_directory);
                assert_eq!(events.len(), 1);
                assert_eq!(events[0]["payload"]["reason_code"], body["error_code"]);
                if model_lookup {
                    assert_eq!(events[0]["payload"]["target_model_call_id"], MODEL_CALL_ID);
                } else {
                    assert!(
                        super::parse_lower_hex_32(
                            events[0]["payload"]["query_digest"].as_str().unwrap()
                        )
                        .is_some()
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn analytical_query_audit_failure_withholds_index_results() {
        for model_lookup in [false, true] {
            let mock = test::Mock::new();
            if model_lookup {
                mock.add(test::handlers::provide(Vec::<ModelRow>::new()));
            } else {
                mock.add(test::handlers::provide([search_event(
                    "ev_018f2a3b-4c5d-7000-8000-000000000001",
                    20,
                )]));
            }
            let fixture = Fixture::with_index(
                10,
                if model_lookup {
                    ManagementRole::Observer
                } else {
                    ManagementRole::Investigator
                },
                Client::default().with_mock(&mock),
            );
            std::thread::scope(|scope| {
                let journal = &fixture.control.access_journal;
                assert!(
                    scope
                        .spawn(move || {
                            let _guard = journal.lock().unwrap();
                            panic!("simulate failed audit writer");
                        })
                        .join()
                        .is_err()
                );
            });
            let response = router(fixture.control)
                .oneshot(analytical_http_request(model_lookup))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert_eq!(body["error_code"], "AUDIT_DURABILITY_FAILED");
            assert!(body.get("events").is_none());
            assert!(body.get("model_call").is_none());
        }
    }

    #[tokio::test]
    async fn analytical_queries_keep_shared_capacity_through_disconnect_and_audit() {
        for model_lookup in [false, true] {
            let started = std::sync::Arc::new(tokio::sync::Notify::new());
            let released = std::sync::Arc::new(tokio::sync::Notify::new());
            let handler_started = started.clone();
            let handler_released = released.clone();
            let index = axum::Router::new().route(
                "/",
                axum::routing::post(move || {
                    let started = handler_started.clone();
                    let released = handler_released.clone();
                    async move {
                        started.notify_one();
                        released.notified().await;
                        StatusCode::OK
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, index).await.unwrap();
            });
            let mut fixture = Fixture::with_index(
                10,
                ManagementRole::Investigator,
                Client::default()
                    .with_url(format!("http://{address}"))
                    .with_validation(false),
            );
            fixture.control.config.principal = ManagementPrincipal::new(
                "operator-1",
                [ManagementRole::Observer, ManagementRole::Investigator],
                [(
                    fixture.control.config.tenant_id.clone(),
                    fixture.control.config.site_id.clone(),
                )],
            )
            .unwrap();
            let capacity = fixture.control.search_capacity.clone();
            let app = router(fixture.control);
            let client = tokio::spawn(app.clone().oneshot(analytical_http_request(model_lookup)));
            tokio::time::timeout(Duration::from_secs(2), started.notified())
                .await
                .unwrap();
            client.abort();
            assert!(client.await.unwrap_err().is_cancelled());
            assert_eq!(capacity.available_permits(), 0);
            let response = app
                .oneshot(analytical_http_request(!model_lookup))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            released.notify_one();
            let _permit = tokio::time::timeout(Duration::from_secs(2), capacity.acquire())
                .await
                .unwrap()
                .unwrap();
            let events = read_access_events(&fixture.access_directory);
            assert_eq!(events.len(), 2);
            let reasons = events
                .iter()
                .map(|event| event["payload"]["reason_code"].as_str().unwrap())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                reasons,
                std::collections::BTreeSet::from([
                    "CONTROL_QUERY_CAPACITY_EXHAUSTED",
                    if model_lookup {
                        "CONTROL_MODEL_CALL_READ"
                    } else {
                        "CONTROL_QUERY_EXECUTED"
                    }
                ])
            );
            server.abort();
        }
    }

    #[tokio::test]
    #[ignore = "requires Node.js 22"]
    #[allow(clippy::too_many_lines)]
    async fn console_client_reads_real_http_wire_contract() {
        let occurred_at = DateTime::parse_from_rfc3339("2026-09-20T08:10:30.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let mock = test::Mock::new();
        mock.add(test::handlers::provide([SummaryRow {
            event_count: 2,
            first_occurred_at: occurred_at,
            last_occurred_at: occurred_at,
            method: "POST".to_owned(),
            operation_id: "orders.create".to_owned(),
            decision: "ALLOW".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            status: Some(201),
            origin_state: "response_received".to_owned(),
            duration_us: 42,
            forwarded: 1,
            terminal: 1,
        }]));
        mock.add(test::handlers::provide([RequestStageSummary {
            stage: "admission".to_owned(),
            outcome: "PASS".to_owned(),
            reason_code: "POLICY_ALLOWED".to_owned(),
            proof_kind: "deterministic".to_owned(),
            confidence: None,
            confidence_status: "not_applicable".to_owned(),
            first_request_seq: 1,
            last_request_seq: 1,
            duration_us: 10,
            event_count: 1,
        }]));
        let mut first = event_summary("ev_018f2a3b-4c5d-7000-8000-000000000001", 1);
        first.occurred_at = occurred_at;
        first.evidence_refs = vec![
            "artifact_018f2a3b-4c5d-7000-8000-000000000011".to_owned(),
            "stg_018f2a3b-4c5d-7000-8000-000000000012".to_owned(),
        ];
        let mut last = event_summary("ev_018f2a3b-4c5d-7000-8000-000000000002", 2);
        last.occurred_at = occurred_at;
        last.event_type = "origin.response".to_owned();
        last.outcome = "response_received".to_owned();
        last.stage.clear();
        last.proof_kind.clear();
        last.confidence_status.clear();
        mock.add(test::handlers::provide([first, last.clone()]));
        mock.add(test::handlers::provide([last]));
        let model_id = "mdl_018f2a3b-4c5d-7000-8000-000000000001";
        let input = "artifact_018f2a3b-4c5d-7000-8000-000000000011";
        let output = "artifact_018f2a3b-4c5d-7000-8000-000000000012";
        let call = "artifact_018f2a3b-4c5d-7000-8000-000000000013";
        let model_rows: Vec<_> = [
            ("started", "model.started", "MODEL_EVALUATION_STARTED"),
            ("requested", "model.requested", "MODEL_REQUESTED"),
            ("success", "model.responded", "MODEL_EVALUATED"),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (status, event_type, reason))| {
            let evidence_refs = match index {
                0 => vec![],
                1 => vec![input.to_owned()],
                _ => vec![input.to_owned(), output.to_owned(), call.to_owned()],
            };
            ModelRow {
                event_id: format!("ev_018f2a3b-4c5d-7000-8000-{:012}", index + 21),
                event_type: event_type.to_owned(),
                request_id: "req_018f2a3b-4c5d-7000-8000-000000000001".to_owned(),
                occurred_at,
                request_seq: u32::try_from(index + 1).unwrap(),
                evidence_refs,
                cause_event_ids: if index == 0 {
                    vec![]
                } else {
                    vec![format!("ev_018f2a3b-4c5d-7000-8000-{:012}", index + 20)]
                },
                sensitivity: "RESTRICTED".to_owned(),
                payload_json: serde_json::json!({
                    "model_call_id": model_id,
                    "provider": "vercel_ai_gateway",
                    "provider_model_id": "typesafe-ai/jev",
                    "model_revision": "jev-1.13.0",
                    "prompt_revision": "evaluation-r1",
                    "question_type": "choice",
                    "status": status,
                    "reason_code": reason,
                    "confidence": if index == 2 { Some(0.8) } else { None },
                    "confidence_status": if index == 2 { "provided" } else { "unavailable" },
                    "duration_us": 1200,
                    "input_artifact_id": if index > 0 { Some(input) } else { None },
                    "output_artifact_id": if index == 2 { Some(output) } else { None },
                    "call_artifact_id": if index == 2 { Some(call) } else { None }
                })
                .to_string(),
            }
        })
        .collect();
        // A retained historical Noul suffix has no provider pair in its payload.
        let mut historical = model_rows.last().unwrap().clone();
        let mut payload: Value = serde_json::from_str(&historical.payload_json).unwrap();
        let payload_object = payload.as_object_mut().unwrap();
        payload_object.remove("provider");
        payload_object.remove("provider_model_id");
        payload_object.insert("question_type".to_owned(), "noul".into());
        payload_object.insert("confidence".to_owned(), Value::Null);
        payload_object.insert("confidence_status".to_owned(), "not_applicable".into());
        historical.payload_json = payload.to_string();
        mock.add(test::handlers::provide(model_rows));
        mock.add(test::handlers::provide([historical]));
        mock.add(test::handlers::provide(Vec::<ModelRow>::new()));
        mock.add(test::handlers::exception(158));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut fixture = Fixture::with_index(
            20,
            ManagementRole::Observer,
            Client::default().with_mock(&mock),
        );
        // A closed pool gives catalog routes deterministic dependency failures.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://xshield:xshield@127.0.0.1:1/xshield")
            .unwrap();
        pool.close().await;
        fixture.control.catalog = PostgresIdentityStore::from_pool(pool);
        let root = fixture.access_directory.parent().unwrap().to_path_buf();
        let access = fixture.access_directory;
        let server =
            tokio::spawn(async move { axum::serve(listener, router(fixture.control)).await });
        let result = run_console_wire("control-wire.ts", address, None).await;
        server.abort();
        let stopped = server.await;
        let events = read_access_events(&access);
        // This root belongs exclusively to the fixture created above.
        fs::remove_dir_all(&root).unwrap();
        assert!(stopped.is_err_and(|error| error.is_cancelled()));
        let status = result.unwrap();
        assert!(
            status.success(),
            "console wire contract failed; phase={:?}",
            status.code()
        );
        assert_eq!(events.len(), 10);
        let model_reads: Vec<_> = events
            .iter()
            .filter(|event| event["event_type"] == "console.model.read")
            .collect();
        assert_eq!(model_reads.len(), 4);
        for event in &model_reads {
            assert_eq!(event["payload"]["target_model_call_id"], model_id);
        }
        assert!(
            model_reads[..3]
                .iter()
                .all(|event| { event["payload"]["reason_code"] == "CONTROL_MODEL_CALL_READ" })
        );
        assert_eq!(
            model_reads[3]["payload"]["reason_code"],
            "CONTROL_QUERY_BUDGET_EXCEEDED"
        );
        assert_eq!(model_reads[0]["evidence_refs"].as_array().unwrap().len(), 3);
        assert!(
            model_reads[2]["evidence_refs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            events.last().unwrap()["payload"]["reason_code"],
            "CONTROL_AUTH_REQUIRED"
        );
    }

    #[tokio::test]
    #[ignore = "requires Node.js 22"]
    #[allow(clippy::too_many_lines)]
    async fn console_client_searches_real_http_wire_contract() {
        let occurred_at = DateTime::parse_from_rfc3339("2026-09-20T08:10:30.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut first = search_event("ev_018f2a3b-4c5d-7000-8000-000000000003", 0);
        first.occurred_at = occurred_at;
        first.event_type = "grant.issued".to_owned();
        first.request_id = None;
        first.stage = None;
        first.outcome = None;
        first.reason_code = None;
        first.proof_kind = None;
        first.confidence_status = None;
        let mut second = search_event("ev_018f2a3b-4c5d-7000-8000-000000000001", 0);
        second.occurred_at = occurred_at + chrono::Duration::microseconds(333);
        second.event_type = "grant.issued".to_owned();
        let mut third = second.clone();
        third.event_id = "ev_018f2a3b-4c5d-7000-8000-000000000002".to_owned();
        // Synthetic index rows exercise the real control HTTP serialization.
        let mock = test::Mock::new();
        mock.add(test::handlers::provide_with_summary(
            [first.clone(), second.clone(), third.clone()],
            r#"{"read_rows":"42","read_bytes":"512"}"#,
        ));
        mock.add(test::handlers::provide([third.clone()]));
        mock.add(test::handlers::provide([third, second, first.clone()]));
        mock.add(test::handlers::provide([first]));
        mock.add(test::handlers::exception(158));
        let mut investigator = Fixture::with_index(
            20,
            ManagementRole::Investigator,
            Client::default().with_mock(&mock),
        );
        investigator.control.config.limits.max_query_events = 2;
        let observer = Fixture::new(20, ManagementRole::Observer);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let observer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let observer_address = observer_listener.local_addr().unwrap();
        let server =
            tokio::spawn(async move { axum::serve(listener, router(investigator.control)).await });
        let observer_server =
            tokio::spawn(
                async move { axum::serve(observer_listener, router(observer.control)).await },
            );
        let result = run_console_wire("search-wire.ts", address, Some(observer_address)).await;
        server.abort();
        observer_server.abort();
        let stopped = server.await;
        let observer_stopped = observer_server.await;
        let mut events = read_access_events(&investigator.access_directory);
        events.extend(read_access_events(&observer.access_directory));
        for access in [&investigator.access_directory, &observer.access_directory] {
            // Each root belongs exclusively to the fixture created above.
            fs::remove_dir_all(access.parent().unwrap()).unwrap();
        }
        assert!(stopped.is_err_and(|error| error.is_cancelled()));
        assert!(observer_stopped.is_err_and(|error| error.is_cancelled()));
        let status = result.unwrap();
        assert!(
            status.success(),
            "console search wire contract failed; phase={:?}",
            status.code()
        );
        let digest = |sort| {
            let canonical = format!(
                "{}|{}|{sort}|2|event_type=grant.issued|grant_id=grant_018f2a3b-4c5d-7000-8000-000000000101|auth_binding_id=auth_018f2a3b-4c5d-7000-8000-000000000102",
                occurred_at.timestamp() - 30,
                occurred_at.timestamp() + 30,
            );
            super::lower_hex(&openssl::sha::sha256(canonical.as_bytes()))
        };
        let ascending = digest("asc");
        let descending = digest("desc");
        let expected = [
            ("CONTROL_QUERY_EXECUTED", "PASS", Some(&ascending)),
            ("CONTROL_QUERY_EXECUTED", "PASS", Some(&ascending)),
            ("CONTROL_QUERY_EXECUTED", "PASS", Some(&descending)),
            ("CONTROL_QUERY_EXECUTED", "PASS", Some(&descending)),
            ("CONTROL_QUERY_BUDGET_EXCEEDED", "DENY", Some(&ascending)),
            ("CONTROL_CURSOR_INVALID", "DENY", Some(&ascending)),
            ("CONTROL_SCOPE_DENIED", "DENY", None),
        ];
        assert_eq!(events.len(), expected.len());
        let mut request_ids = std::collections::BTreeSet::new();
        for (event, (reason, outcome, digest)) in events.iter().zip(expected) {
            assert_eq!(event["event_type"], "console.query.executed");
            assert_eq!(event["tenant_id"], "tenant_a");
            assert_eq!(event["site_id"], "site_a");
            assert!(request_ids.insert(event["request_id"].as_str().unwrap()));
            assert_eq!(event["payload"]["method"], "POST");
            assert_eq!(event["payload"]["path"], super::search::SEARCH_PATH);
            assert_eq!(event["payload"]["subject_ref"], "operator-1");
            assert_eq!(event["payload"]["reason_code"], reason);
            assert_eq!(event["payload"]["outcome"], outcome);
            assert_eq!(
                event["payload"]["query_digest"],
                digest.map_or(Value::Null, |value| Value::from(value.as_str()))
            );
            assert!(event["payload"]["target_request_id"].is_null());
            assert!(event["payload"].get("filters").is_none());
            assert!(event["payload"].get("cursor").is_none());
            assert_eq!(event["evidence_refs"], json!([]));
        }
    }

    async fn run_console_wire(
        script_name: &str,
        address: std::net::SocketAddr,
        observer_address: Option<std::net::SocketAddr>,
    ) -> Result<std::process::ExitStatus, &'static str> {
        run_console_wire_with_env(script_name, address, observer_address, Vec::new()).await
    }

    async fn run_console_wire_with_env(
        script_name: &str,
        address: std::net::SocketAddr,
        observer_address: Option<std::net::SocketAddr>,
        environment: Vec<(&'static str, String)>,
    ) -> Result<std::process::ExitStatus, &'static str> {
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../web/console/tests")
            .join(script_name);
        tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new("node");
            command.envs(environment);
            if let Some(address) = observer_address {
                command.env(
                    "XSHIELD_CONSOLE_TEST_OBSERVER_ORIGIN",
                    format!("http://{address}"),
                );
            }
            let mut child = command
                .arg("--experimental-strip-types")
                .arg(script)
                .env("XSHIELD_CONSOLE_TEST_ORIGIN", format!("http://{address}"))
                .env("XSHIELD_CONSOLE_TEST_TOKEN", TOKEN)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|_| "Node.js 22 is required")?;
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => return Ok(status),
                    Ok(None) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    _ => {
                        child.kill().map_err(|_| "Node cleanup failed")?;
                        child.wait().map_err(|_| "Node wait failed")?;
                        return Err("Node contract test exceeded its execution budget");
                    }
                }
            }
        })
        .await
        .map_err(|_| "Node contract task failed")?
    }

    fn private_directory(path: &Path) {
        fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
