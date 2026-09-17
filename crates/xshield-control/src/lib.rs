//! Authenticated control-plane HTTP endpoints and their mandatory access audit.
//!
//! The control plane uses an independently provisioned management credential,
//! server-derived tenant/site scope, and a separate encrypted audit producer.

#![warn(missing_docs)]

use axum::{
    Json, Router,
    extract::State,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{SecondsFormat, Utc};
use openssl::{memcmp, sha::sha256};
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
    domain::{EventId, SiteId, TenantId},
};
use xshield_worker::{
    PublicationHealth, PublishError, PublisherConfig, inspect_publication_health,
};

const HEALTH_PATH: &str = "/control/v1/audit/health";
const RATE_WINDOW: Duration = Duration::from_mins(1);
const TOKEN_BYTES_MAX: usize = 512;
const TOKEN_LIFETIME_MAX_SECONDS: u64 = 24 * 60 * 60;

/// Time-bounded management bearer material reduced to a one-way digest.
pub struct ManagementCredential {
    token_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
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
    principal: ManagementPrincipal,
    tenant_id: TenantId,
    site_id: SiteId,
    publisher: PublisherConfig,
    source_journal_key_id: String,
    rate_limit: u64,
}

impl ControlConfig {
    /// Builds a single-scope control configuration from trusted startup input.
    ///
    /// The bearer token is reduced to a digest immediately. Tenant and site are
    /// server-derived and are not accepted from the HTTP request.
    ///
    /// # Errors
    /// Returns [`ControlError::InvalidConfig`] for a weak or malformed scalar.
    pub fn new(
        credential: ManagementCredential,
        principal: ManagementPrincipal,
        tenant_id: TenantId,
        site_id: SiteId,
        publisher: PublisherConfig,
        source_journal_key_id: impl Into<String>,
        rate_limit: u64,
    ) -> Result<Self, ControlError> {
        let source_journal_key_id = source_journal_key_id.into();
        if source_journal_key_id.is_empty()
            || source_journal_key_id.len() > 128
            || source_journal_key_id.chars().any(char::is_control)
            || rate_limit == 0
        {
            return Err(ControlError::InvalidConfig);
        }
        Ok(Self {
            credential,
            principal,
            tenant_id,
            site_id,
            publisher,
            source_journal_key_id,
            rate_limit,
        })
    }
}

/// Runtime state for the authenticated audit-health endpoint.
pub struct ControlPlane {
    config: ControlConfig,
    source_journal_key: JournalKey,
    seal_key: SealVerifyingKey,
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
        access_journal: LocalJournal,
    ) -> Self {
        let rate_limit = config.rate_limit;
        Self {
            unauthenticated_rate: Mutex::new(RateWindow::new(rate_limit)),
            rate: Mutex::new(RateWindow::new(rate_limit)),
            config,
            source_journal_key,
            seal_key,
            access_journal: Mutex::new(access_journal),
        }
    }

    fn health(&self, authorization: Option<&str>) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let subject = match self.authenticated_subject(authorization, &request_id) {
            Ok(subject) => subject,
            Err(response) => return *response,
        };
        let Ok(mut rate) = self.rate.lock() else {
            return self.audited_error(
                &request_id,
                Some(subject),
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_RATE_UNAVAILABLE",
                "management service unavailable",
                true,
                "retry_later",
            );
        };
        let within_budget = rate.take(Instant::now());
        drop(rate);
        if !within_budget {
            return self.audited_error(
                &request_id,
                Some(subject),
                StatusCode::TOO_MANY_REQUESTS,
                "CONTROL_RATE_LIMITED",
                "management request rate exceeded",
                true,
                "retry_later",
            );
        }

        let Ok(health) = inspect_publication_health(
            &self.config.publisher,
            &self.config.source_journal_key_id,
            &self.source_journal_key,
            &self.seal_key,
        ) else {
            return self.audited_error(
                &request_id,
                Some(subject),
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_HEALTH_UNAVAILABLE",
                "audit health is temporarily unavailable",
                true,
                "retry_later",
            );
        };
        if self
            .append_access_event(&request_id, Some(subject), "PASS", "CONTROL_HEALTH_READ")
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

    fn authenticated_subject<'a>(
        &'a self,
        authorization: Option<&str>,
        request_id: &str,
    ) -> Result<&'a str, Box<EndpointResult>> {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return Err(Box::new(self.audited_error(
                request_id,
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
                StatusCode::UNAUTHORIZED,
                "CONTROL_AUTH_REQUIRED",
                "management authentication required",
                false,
                "authenticate",
            )));
        }

        let subject = self.config.principal.subject();
        if !self.config.principal.authorizes(
            ManagementRole::AuditAdministrator,
            &self.config.tenant_id,
            &self.config.site_id,
        ) {
            return Err(Box::new(self.audited_error(
                request_id,
                Some(subject),
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
        status: StatusCode,
        reason_code: &'static str,
        message_safe: &'static str,
        retryable: bool,
        next_action: &'static str,
    ) -> EndpointResult {
        if self
            .append_access_event(request_id, subject, "DENY", reason_code)
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
        outcome: &'static str,
        reason_code: &'static str,
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
            event_type: "console.health.read",
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
            evidence_refs: &[],
            cause_event_ids: &[],
            payload: AccessPayload {
                method: "GET",
                path: HEALTH_PATH,
                subject_ref,
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
        .with_state(Arc::new(control))
}

async fn health_handler(State(control): State<Arc<ControlPlane>>, headers: HeaderMap) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    match tokio::task::spawn_blocking(move || control.health(authorization.as_deref())).await {
        Ok(result) => result.into_response(),
        Err(_) => no_store(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error_code: "CONTROL_INTERNAL",
                    message_safe: "management service unavailable",
                    request_id: format!("req_{}", Uuid::now_v7()),
                    retryable: true,
                    next_action: "retry_later",
                }),
            )
                .into_response(),
        ),
    }
}

enum EndpointResult {
    Success(HealthResponse),
    Error(StatusCode, ErrorResponse),
}

impl IntoResponse for EndpointResult {
    fn into_response(self) -> Response {
        no_store(match self {
            Self::Success(response) => (StatusCode::OK, Json(response)).into_response(),
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
    use super::{ControlConfig, ControlPlane, ManagementCredential, router};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header::AUTHORIZATION},
    };
    use serde_json::Value;
    use std::{
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;
    use uuid::Uuid;
    use xshield_audit::{
        JournalKey, JournalLimits, LocalJournal, SealSigningKey, SealVerifyingKey,
        SealedSegmentReader, seal_closed_segments,
    };
    use xshield_core::{
        admin::{ManagementPrincipal, ManagementRole},
        domain::{SiteId, TenantId},
    };
    use xshield_worker::PublisherConfig;

    const JOURNAL_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SEAL_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const TOKEN: &str = "test-control-token-32-bytes-long-value";

    #[tokio::test]
    async fn enforces_auth_scope_rate_limit_and_health_contract() {
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

        let limited = app.oneshot(authenticated_request()).await.unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_access_events(&fixture.access_directory, 3);

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

    fn authenticated_request() -> Request<Body> {
        Request::get(super::HEALTH_PATH)
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap()
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

        fn with_window(
            rate_limit: u64,
            role: ManagementRole,
            token_issued_at: u64,
            token_expires_at: u64,
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
                1024 * 1024,
            )
            .unwrap();
            let credential =
                ManagementCredential::new(TOKEN, token_issued_at, token_expires_at).unwrap();
            let config = ControlConfig::new(
                credential,
                principal,
                tenant,
                site,
                publisher,
                "journal-key-r1",
                rate_limit,
            )
            .unwrap();
            let seal_key = test_seal_key();
            Self {
                control: ControlPlane::new(
                    config,
                    JournalKey::from_hex(JOURNAL_KEY).unwrap(),
                    seal_key,
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

    fn assert_access_events(directory: &Path, expected: usize) {
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
        assert_eq!(segments.len(), expected);
        let verifier = signing.verifying_key().unwrap();
        for segment in segments {
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
            assert_eq!(event["event_type"], "console.health.read");
            assert!(event["payload"]["reason_code"].is_string());
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
