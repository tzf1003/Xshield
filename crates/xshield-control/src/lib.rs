//! Authenticated control-plane HTTP endpoints and their mandatory access audit.
//!
//! The control plane uses an independently provisioned management credential,
//! server-derived tenant/site scope, and a separate encrypted audit producer.

#![warn(missing_docs)]

use axum::{
    Json, Router,
    extract::{Path, RawQuery, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{SecondsFormat, Utc};
use clickhouse::Client;
use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sha::sha256, sign::Signer};
use serde::Serialize;
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use xshield_audit::{JournalError, JournalKey, JournalRecord, LocalJournal, SealVerifyingKey};
use xshield_core::{
    admin::{ManagementPrincipal, ManagementRole},
    domain::{ArtifactId, EventId, RequestId, SiteId, TenantId},
};
use xshield_evidence::EvidenceManifest;
use xshield_postgres::{
    EvidenceCatalogArtifactQuery, EvidenceCatalogPage, EvidenceCatalogQuery, PostgresIdentityStore,
};
use xshield_worker::{
    IndexWatermark, PublicationHealth, PublishError, PublisherConfig, RequestEventPosition,
    RequestEvents, RequestSummary, inspect_publication_health, query_request_events,
    query_request_summary,
};
use zeroize::Zeroizing;

const HEALTH_PATH: &str = "/control/v1/audit/health";
const REQUEST_SUMMARY_PATH: &str = "/control/v1/requests/{request_id}";
const REQUEST_EVENTS_PATH: &str = "/control/v1/requests/{request_id}/events";
const REQUEST_EVIDENCE_PATH: &str = "/control/v1/requests/{request_id}/evidence";
const ARTIFACT_PATH: &str = "/control/v1/artifacts/{artifact_id}";
const RATE_WINDOW: Duration = Duration::from_mins(1);
const TOKEN_BYTES_MAX: usize = 512;
const TOKEN_LIFETIME_MAX_SECONDS: u64 = 24 * 60 * 60;
const MAX_QUERY_EVENTS: u16 = 1_000;
const MAX_QUERY_ARTIFACTS: u16 = 128;
const CURSOR_BYTES_MAX: usize = 160;
const CURSOR_VERSION: &str = "v1";

#[derive(Clone, Copy)]
struct AccessAction {
    event_type: &'static str,
    path: &'static str,
    role: ManagementRole,
}

const HEALTH_ACCESS: AccessAction = AccessAction {
    event_type: "console.health.read",
    path: HEALTH_PATH,
    role: ManagementRole::AuditAdministrator,
};
const REQUEST_EVENTS_ACCESS: AccessAction = AccessAction {
    event_type: "console.events.read",
    path: REQUEST_EVENTS_PATH,
    role: ManagementRole::Observer,
};
const REQUEST_SUMMARY_ACCESS: AccessAction = AccessAction {
    event_type: "console.request.read",
    path: REQUEST_SUMMARY_PATH,
    role: ManagementRole::Observer,
};
const REQUEST_EVIDENCE_ACCESS: AccessAction = AccessAction {
    event_type: "console.manifest.read",
    path: REQUEST_EVIDENCE_PATH,
    role: ManagementRole::Observer,
};
const ARTIFACT_ACCESS: AccessAction = AccessAction {
    event_type: "console.manifest.read",
    path: ARTIFACT_PATH,
    role: ManagementRole::Observer,
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

/// Validated request-rate and query-result ceilings for one control process.
#[derive(Clone, Copy)]
pub struct ControlLimits {
    requests_per_minute: u64,
    max_query_events: u16,
    max_query_artifacts: u16,
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
    ) -> Result<Self, ControlError> {
        if requests_per_minute == 0
            || !(1..=MAX_QUERY_EVENTS).contains(&max_query_events)
            || !(1..=MAX_QUERY_ARTIFACTS).contains(&max_query_artifacts)
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(Self {
            requests_per_minute,
            max_query_events,
            max_query_artifacts,
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
        principal: ManagementPrincipal,
        tenant_id: TenantId,
        site_id: SiteId,
        publisher: PublisherConfig,
        source_journal_key_id: impl Into<String>,
        limits: ControlLimits,
    ) -> Result<Self, ControlError> {
        let source_journal_key_id = source_journal_key_id.into();
        if source_journal_key_id.is_empty()
            || source_journal_key_id.len() > 128
            || source_journal_key_id.chars().any(char::is_control)
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(Self {
            credential,
            cursor_key,
            principal,
            tenant_id,
            site_id,
            publisher,
            source_journal_key_id,
            limits,
        })
    }
}

/// Runtime state for the authenticated audit-health endpoint.
pub struct ControlPlane {
    config: ControlConfig,
    source_journal_key: JournalKey,
    seal_key: SealVerifyingKey,
    index: Client,
    catalog: PostgresIdentityStore,
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
            catalog,
            access_journal: Mutex::new(access_journal),
        }
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
                "DENY",
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
            outcome,
            reason_code,
            &[],
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
        outcome: &'static str,
        reason_code: &'static str,
        evidence_refs: &[&str],
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
                method: "GET",
                path: action.path,
                subject_ref,
                target_request_id: target_request_id.map(RequestId::as_str),
                target_artifact_id: target_artifact_id.map(ArtifactId::as_str),
                outcome,
                reason_code,
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

/// Builds the v1 management router. The route performs no production replay or
/// mutation; its only side effect is the required durable access event.
pub fn router(control: ControlPlane) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health_handler))
        .route(REQUEST_SUMMARY_PATH, get(request_summary_handler))
        .route(REQUEST_EVENTS_PATH, get(request_events_handler))
        .route(REQUEST_EVIDENCE_PATH, get(request_evidence_handler))
        .route(ARTIFACT_PATH, get(artifact_handler))
        .with_state(Arc::new(control))
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

enum EndpointResult {
    Success(HealthResponse),
    RequestSummary(RequestSummaryResponse),
    RequestEvents(RequestEventsResponse),
    RequestEvidence(RequestEvidenceResponse),
    Artifact(ArtifactResponse),
    Error(StatusCode, ErrorResponse),
}

impl IntoResponse for EndpointResult {
    fn into_response(self) -> Response {
        no_store(match self {
            Self::Success(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::RequestSummary(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::RequestEvents(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::RequestEvidence(response) => (StatusCode::OK, Json(response)).into_response(),
            Self::Artifact(response) => (StatusCode::OK, Json(response)).into_response(),
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
    outcome: &'a str,
    reason_code: &'a str,
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
    use super::{
        ControlConfig, ControlLimits, ControlPlane, CursorKey, ManagementCredential, router,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header::AUTHORIZATION},
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
    const TOKEN: &str = "test-control-token-32-bytes-long-value";
    const MISSING_ARTIFACT_ID: &str = "artifact_018f2a3b-4c5d-7000-8000-000000000999";

    #[tokio::test]
    async fn enforces_auth_scope_rate_limit_and_health_contract() {
        assert!(CursorKey::from_hex("not-a-key").is_err());
        assert!(ControlLimits::new(0, 100, 1).is_err());
        assert!(ControlLimits::new(1, 1_001, 1).is_err());
        assert!(ControlLimits::new(1, 1, 129).is_err());
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
            &[0],
        );
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
                ManagementPrincipal::new("operator-1", [role], [(tenant.clone(), site.clone())])
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
                principal,
                tenant,
                site,
                publisher,
                "journal-key-r1",
                ControlLimits::new(rate_limit, 1, max_query_artifacts).unwrap(),
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
            &vec![0; target_request_ids.len()],
        );
    }

    fn assert_access_event_targets_and_evidence(
        directory: &Path,
        event_type: &str,
        target_request_ids: &[Option<&str>],
        target_artifact_ids: &[Option<&str>],
        evidence_counts: &[usize],
    ) {
        assert_eq!(target_request_ids.len(), evidence_counts.len());
        assert_eq!(target_artifact_ids.len(), evidence_counts.len());
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
        assert_eq!(segments.len(), target_request_ids.len());
        let verifier = signing.verifying_key().unwrap();
        for (((segment, target_request_id), target_artifact_id), evidence_count) in segments
            .into_iter()
            .zip(target_request_ids)
            .zip(target_artifact_ids)
            .zip(evidence_counts)
        {
            let path = directory.join(format!("segment-{}.closed.xja", segment.producer_boot_id));
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
            assert_eq!(event["event_type"], event_type);
            assert_eq!(
                event["evidence_refs"].as_array().unwrap().len(),
                *evidence_count
            );
            assert!(event["payload"]["reason_code"].is_string());
            assert_eq!(
                event["payload"]["target_request_id"],
                target_request_id.map_or(Value::Null, Value::from)
            );
            assert_eq!(
                event["payload"]["target_artifact_id"],
                target_artifact_id.map_or(Value::Null, Value::from)
            );
            assert!(reader.next_record().unwrap().is_none());
        }
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
