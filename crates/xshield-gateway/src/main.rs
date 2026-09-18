mod buffered_json;
mod durable_audit;
mod protected_identity;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::{
    Error as PingoraError, ErrorType, Result as PingoraResult,
    http::ResponseHeader,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
    upstreams::peer::HttpPeer,
};
use std::{
    env,
    error::Error,
    fs,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use xshield_audit::JournalKey;
use xshield_core::{audit::ReasonCode, domain::RequestId, identity::UnixSeconds};
use xshield_gateway::request_crypto::{
    FrozenRequest, KeyAccessPort, KeyAccessQuery, RequestCryptoPolicy,
};
use xshield_gateway::response_crypto::{
    ENCRYPTED_RESPONSE_CONTENT_TYPE, ResponseKeyAccessPort, ResponseKeyAccessQuery,
};
use xshield_gateway::{
    GatewayConfig, GatewayDecision, GatewayOutcome, MAX_BUFFERED_BODY_IN_FLIGHT_BYTES,
    MAX_CONFIG_BYTES,
};
use xshield_postgres::{
    PostgresIdentityStore, RequestCryptoMessage, RequestCryptoMessageOutcome, StoreError,
};
use zeroize::Zeroizing;

use crate::buffered_json::BufferedJsonResponse;
use crate::durable_audit::{
    AdmissionAudit, AdmissionFacts, DurableAudit, FinalFacts, RequestCryptoAudit,
    ResponseCryptoAudit, new_trace_id,
};
use crate::protected_identity::{
    PendingAuthBinding, ProtectedIdentity, ResponseIdentity, WAF_COOKIE, store_failure_reason,
    strip_edge_proofs,
};

const ENCRYPTED_REQUEST_CONTENT_TYPE: &str = "application/vnd.xshield.encrypted+json";

struct Gateway {
    config: Arc<GatewayConfig>,
    audit: DurableAudit,
    identity: Option<ProtectedIdentity>,
    request_key: Option<EnvRequestKey>,
    response_key: Option<EnvResponseKey>,
    postgres: Option<Arc<PostgresRuntime>>,
    buffered_body_budget: Arc<Semaphore>,
}

struct PostgresRuntime {
    database_url: Zeroizing<String>,
    max_connections: u32,
    acquire_timeout: Duration,
    store: tokio::sync::OnceCell<PostgresIdentityStore>,
}

impl PostgresRuntime {
    fn from_env(config: xshield_gateway::IdentityStoreConfig) -> Result<Self, env::VarError> {
        Ok(Self {
            database_url: Zeroizing::new(env::var("XSHIELD_DATABASE_URL")?),
            max_connections: config.max_connections(),
            acquire_timeout: Duration::from_millis(config.acquire_timeout_ms()),
            store: tokio::sync::OnceCell::new(),
        })
    }

    async fn store(&self) -> Result<&PostgresIdentityStore, StoreError> {
        self.store
            .get_or_try_init(|| async {
                PostgresIdentityStore::connect(
                    &self.database_url,
                    self.max_connections,
                    self.acquire_timeout,
                )
                .await
            })
            .await
    }
}

struct RequestContext {
    request_id: String,
    trace_id: String,
    started_at: Instant,
    decision: Option<GatewayDecision>,
    admission_audit: Option<AdmissionAudit>,
    rebuilt_request_body: Option<Bytes>,
    rebuilt_request_len: Option<usize>,
    request_crypto_audit: Option<RequestCryptoAudit>,
    response_crypto_audit: Option<ResponseCryptoAudit>,
    buffered_response: Option<BufferedJsonResponse>,
    response_identity: Option<ResponseIdentity>,
    anonymous_session_cookie: Option<String>,
    pending_auth_binding: Option<PendingAuthBinding>,
    response_failure: Option<ReasonCode>,
    origin_status: Option<u16>,
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            request_id: format!("req_{}", Uuid::now_v7()),
            trace_id: new_trace_id(),
            started_at: Instant::now(),
            decision: None,
            admission_audit: None,
            rebuilt_request_body: None,
            rebuilt_request_len: None,
            request_crypto_audit: None,
            response_crypto_audit: None,
            buffered_response: None,
            response_identity: None,
            anonymous_session_cookie: None,
            pending_auth_binding: None,
            response_failure: None,
            origin_status: None,
        }
    }

    // Admission, request transformation, and the durable forward barrier stay
    // contiguous so no later refactor can dispatch between those checks.
    #[allow(clippy::too_many_lines)]
    async fn request_filter(
        &self,
        session: &mut Session,
        context: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        if !self.audit.is_ready() {
            respond_denial(
                session,
                503,
                &context.request_id,
                ReasonCode::AuditDurabilityFailed,
                None,
            )
            .await?;
            return Ok(true);
        }
        let client_ip = session
            .as_downstream()
            .client_addr()
            .and_then(|address| address.as_inet())
            .map(std::net::SocketAddr::ip);
        let request = session.req_header();
        let method = request.method.as_str().to_owned();
        let path = request.uri.path().to_owned();
        let Ok(wall_time) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            respond_denial(
                session,
                503,
                &context.request_id,
                ReasonCode::ClockUnavailable,
                None,
            )
            .await?;
            return Ok(true);
        };
        let now = UnixSeconds::new(wall_time.as_secs());
        let Ok(request_id) = RequestId::parse(&context.request_id) else {
            respond_denial(
                session,
                503,
                &context.request_id,
                ReasonCode::RequestIncomplete,
                None,
            )
            .await?;
            return Ok(true);
        };
        let mut decision = match self.identity.as_ref() {
            Some(identity) => {
                if let Ok(admission) = identity
                    .admit(&self.config, request, &request_id, client_ip, now)
                    .await
                {
                    context.response_identity = admission.response_identity;
                    context.anonymous_session_cookie = admission.anonymous_session_cookie;
                    admission.decision
                } else {
                    let mut decision = self.config.admit(&method, &path, now);
                    decision.outcome = GatewayOutcome::Denied;
                    decision.reason_code = store_failure_reason();
                    decision
                }
            }
            None => self.config.admit(&method, &path, now),
        };
        self.apply_request_crypto(session, context, &method, &path, now, &mut decision)
            .await;
        let audit_result = self
            .audit
            .commit_admission(AdmissionFacts {
                request_id: &context.request_id,
                trace_id: &context.trace_id,
                method: &method,
                decision: &decision,
                duration_us: elapsed_us(context.started_at),
                request_crypto: context.request_crypto_audit.as_ref(),
            })
            .await;
        let admission_audit = match audit_result {
            Ok(receipt) => receipt,
            Err(error) => {
                self.audit.observe_failure(&error);
                respond_denial(
                    session,
                    503,
                    &context.request_id,
                    ReasonCode::AuditDurabilityFailed,
                    None,
                )
                .await?;
                return Ok(true);
            }
        };
        context.decision = Some(decision.clone());
        context.admission_audit = Some(admission_audit);
        if decision.outcome == GatewayOutcome::Denied {
            respond_denial(
                session,
                denial_status(decision.reason_code),
                &context.request_id,
                decision.reason_code,
                context.anonymous_session_cookie.as_deref(),
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _context: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            self.config.origin_address(),
            self.config.origin_tls(),
            self.config.origin_server_name().to_owned(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        context: &mut Self::CTX,
    ) -> PingoraResult<()> {
        strip_edge_proofs(upstream_request)?;
        if let Some(length) = context.rebuilt_request_len {
            for name in [
                "Transfer-Encoding",
                "Content-Encoding",
                "Expect",
                "Trailer",
                "Content-MD5",
                "Digest",
                "Content-Digest",
                "Repr-Digest",
            ] {
                upstream_request.remove_header(name);
            }
            upstream_request.insert_header("Content-Type", "application/json")?;
            upstream_request.insert_header("Content-Length", length.to_string())?;
        }
        upstream_request.insert_header("Host", self.config.origin_server_name())?;
        upstream_request.insert_header("X-Xshield-Request-Id", &context.request_id)?;
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        context: &mut Self::CTX,
    ) -> PingoraResult<()> {
        if context.rebuilt_request_len.is_none() {
            return Ok(());
        }
        if !end_of_stream {
            return request_error(ReasonCode::RequestEnvelopeInvalid);
        }
        let rebuilt = context.rebuilt_request_body.take().ok_or_else(|| {
            PingoraError::explain(ErrorType::HTTPStatus(502), "rebuilt body missing")
        })?;
        *body = Some(rebuilt);
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        context: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let request = session.req_header();
        let buffered_json_limit = self
            .config
            .buffered_json_max_bytes(request.method.as_str(), request.uri.path());
        let response_crypto_rule = self
            .config
            .response_crypto_rule(request.method.as_str(), request.uri.path());
        if upstream_response.status.as_u16() == 101 && buffered_json_limit.is_some() {
            context.origin_status = Some(101);
            context.response_failure = Some(ReasonCode::ResponseValidationFailed);
            if let Some(rule) = response_crypto_rule {
                context.response_crypto_audit = Some(ResponseCryptoAudit::failed(
                    rule,
                    ReasonCode::ResponseValidationFailed,
                    0,
                ));
            }
            return response_error(ReasonCode::ResponseValidationFailed);
        }
        if !upstream_response.status.is_informational() {
            context.origin_status = Some(upstream_response.status.as_u16());
            if let Some(limit) = buffered_json_limit {
                match BufferedJsonResponse::begin(
                    upstream_response,
                    limit,
                    response_crypto_rule.map_or(
                        limit,
                        xshield_gateway::response_crypto::ResponseCryptoRule::max_in_flight_bytes,
                    ),
                    &self.buffered_body_budget,
                ) {
                    Ok(buffer) => {
                        if let Some(rule) = self
                            .config
                            .auth_binding_rule(request.method.as_str(), request.uri.path())
                        {
                            prepare_auth_response_headers(upstream_response)?;
                            if rule.applies(upstream_response.status.as_u16()) {
                                let now = system_time()?;
                                let pending = ProtectedIdentity::prepare_auth_binding(rule, now)
                                    .map_err(|reason| {
                                        PingoraError::explain(
                                            ErrorType::HTTPStatus(502),
                                            reason.as_str(),
                                        )
                                    })?;
                                // Pingora fixes response headers before its synchronous body
                                // filter runs. This cookie names only an unbound session until
                                // the buffered authentication body commits successfully.
                                append_waf_cookie(
                                    upstream_response,
                                    &pending.cookie_header_value(),
                                )?;
                                context.pending_auth_binding = Some(pending);
                            }
                        } else if self
                            .config
                            .auth_refresh_rule(request.method.as_str(), request.uri.path())
                            .is_some()
                            || self
                                .config
                                .auth_context_switch_rule(
                                    request.method.as_str(),
                                    request.uri.path(),
                                )
                                .is_some()
                        {
                            prepare_auth_response_headers(upstream_response)?;
                        } else if self
                            .config
                            .response_grant_operation(request.method.as_str(), request.uri.path())
                            .is_some()
                        {
                            prepare_grant_response_headers(upstream_response)?;
                        }
                        if response_crypto_rule.is_some() {
                            prepare_encrypted_response_headers(upstream_response)?;
                        }
                        context.buffered_response = Some(buffer);
                    }
                    Err(reason) => {
                        context.response_failure = Some(reason);
                        if let Some(rule) = response_crypto_rule {
                            context.response_crypto_audit =
                                Some(ResponseCryptoAudit::failed(rule, reason, 0));
                        }
                        return response_error(reason);
                    }
                }
            }
        }
        upstream_response.insert_header("X-Xshield-Request-Id", &context.request_id)?;
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        context: &mut Self::CTX,
    ) -> PingoraResult<Option<std::time::Duration>> {
        let Some(buffer) = context.buffered_response.as_mut() else {
            return Ok(None);
        };
        match buffer.filter(body, end_of_stream) {
            Ok(Some(complete)) => {
                let released = self
                    .commit_auth_binding(session, context, complete)
                    .and_then(|body| self.commit_auth_transition(session, context, body))
                    .and_then(|body| self.commit_response_grants(session, context, body))
                    .and_then(|body| self.encrypt_response(session, context, body));
                match released {
                    Ok(released) => *body = Some(released),
                    Err(reason) => {
                        context.response_failure = Some(reason);
                        return response_error(reason);
                    }
                }
            }
            Ok(None) => {}
            Err(reason) => {
                context.response_failure = Some(reason);
                let request = session.req_header();
                if let Some(rule) = self
                    .config
                    .response_crypto_rule(request.method.as_str(), request.uri.path())
                {
                    context.response_crypto_audit =
                        Some(ResponseCryptoAudit::failed(rule, reason, 0));
                }
                return response_error(reason);
            }
        }
        Ok(None)
    }

    async fn response_trailer_filter(
        &self,
        _session: &mut Session,
        upstream_trailers: &mut http::HeaderMap,
        context: &mut Self::CTX,
    ) -> PingoraResult<Option<Bytes>> {
        if let Err(reason) =
            filter_response_trailers(context.buffered_response.is_some(), upstream_trailers)
        {
            context.response_failure = Some(reason);
            return response_error(reason);
        }
        Ok(None)
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        context: &mut Self::CTX,
    ) {
        let status = session
            .response_written()
            .map_or(0, |response| response.status.as_u16());
        let Some(decision) = context.decision.as_ref() else {
            return;
        };
        let Some(admission) = context.admission_audit.as_ref() else {
            return;
        };
        let result = self
            .audit
            .finalize(FinalFacts {
                request_id: &context.request_id,
                trace_id: &context.trace_id,
                method: session.req_header().method.as_str(),
                decision,
                admission,
                status,
                duration_us: elapsed_us(context.started_at),
                proxy_error: error.is_some(),
                response_failure: context.response_failure,
                origin_status: context.origin_status,
                response_crypto: context.response_crypto_audit.as_ref(),
            })
            .await;
        if let Err(error) = result {
            self.audit.observe_failure(&error);
        }
    }
}

impl Gateway {
    async fn apply_request_crypto(
        &self,
        session: &mut Session,
        context: &mut RequestContext,
        method: &str,
        path: &str,
        now: UnixSeconds,
        decision: &mut GatewayDecision,
    ) {
        if decision.outcome != GatewayOutcome::Allowed {
            return;
        }
        let Some(policy) = self.config.request_crypto_policy(method, path) else {
            return;
        };
        let rule = match policy {
            RequestCryptoPolicy::Observe(rule) => {
                context.request_crypto_audit = Some(RequestCryptoAudit::observed(rule));
                return;
            }
            RequestCryptoPolicy::Enforce(rule) => rule,
        };
        let started_at = Instant::now();
        match self
            .decrypt_request(session, rule, now, decision, &context.request_id)
            .await
        {
            Ok(frozen) => {
                context.rebuilt_request_len = Some(frozen.body_len());
                context.request_crypto_audit = Some(RequestCryptoAudit::passed(
                    frozen.evidence(),
                    elapsed_us(started_at),
                ));
                context.rebuilt_request_body = Some(frozen.into_body());
            }
            Err(reason) => {
                context.request_crypto_audit = Some(RequestCryptoAudit::failed(
                    rule,
                    reason,
                    elapsed_us(started_at),
                ));
                decision.outcome = GatewayOutcome::Denied;
                decision.reason_code = reason;
            }
        }
    }

    async fn decrypt_request(
        &self,
        session: &mut Session,
        rule: &xshield_gateway::request_crypto::RequestCryptoRule,
        now: UnixSeconds,
        decision: &GatewayDecision,
        request_id: &str,
    ) -> Result<FrozenRequest, ReasonCode> {
        validate_encrypted_request_headers(session.req_header(), rule.max_envelope_bytes())?;
        let method = session.req_header().method.as_str().to_owned();
        let path = session.req_header().uri.path().to_owned();
        session.as_mut().enable_retry_buffering();
        let permits = u32::try_from(rule.max_in_flight_bytes())
            .map_err(|_| ReasonCode::RequestBufferCapacityExhausted)?;
        let _permit = Arc::clone(&self.buffered_body_budget)
            .try_acquire_many_owned(permits)
            .map_err(|_| ReasonCode::RequestBufferCapacityExhausted)?;
        let mut envelope = Vec::new();
        envelope
            .try_reserve_exact(rule.max_envelope_bytes())
            .map_err(|_| ReasonCode::RequestBufferCapacityExhausted)?;
        while let Some(chunk) = session
            .read_request_body()
            .await
            .map_err(|_| ReasonCode::RequestEnvelopeInvalid)?
        {
            if envelope.len().saturating_add(chunk.len()) > rule.max_envelope_bytes() {
                return Err(ReasonCode::RequestBodyTooLarge);
            }
            envelope.extend_from_slice(&chunk);
        }
        let operation_id = decision
            .operation_id
            .as_ref()
            .ok_or(ReasonCode::RequestEnvelopeInvalid)?;
        let keys = self
            .request_key
            .as_ref()
            .ok_or(ReasonCode::RequestCryptoKeyUnavailable)?;
        let frozen = rule.decode(
            self.config.tenant_id().as_str(),
            self.config.site_id().as_str(),
            operation_id.as_str(),
            &method,
            &path,
            now,
            &envelope,
            keys,
        )?;
        let request_id = RequestId::parse(request_id)
            .map_err(|_| ReasonCode::RequestCryptoReplayStoreUnavailable)?;
        let postgres = self
            .postgres
            .as_ref()
            .ok_or(ReasonCode::RequestCryptoReplayStoreUnavailable)?;
        let message = RequestCryptoMessage::new(
            self.config.tenant_id(),
            self.config.site_id(),
            rule.key_id(),
            frozen.message_id(),
            frozen.nonce(),
            &request_id,
            frozen.expires_at(),
            now,
            rule.max_active_messages(),
        )
        .map_err(|_| ReasonCode::RequestCryptoReplayStoreUnavailable)?;
        let store = postgres
            .store()
            .await
            .map_err(|_| ReasonCode::RequestCryptoReplayStoreUnavailable)?;
        match store
            .consume_request_crypto_message(message)
            .await
            .map_err(|_| ReasonCode::RequestCryptoReplayStoreUnavailable)?
        {
            RequestCryptoMessageOutcome::Consumed => Ok(frozen),
            RequestCryptoMessageOutcome::Replayed => Err(ReasonCode::RequestCryptoReplayDetected),
            RequestCryptoMessageOutcome::CapacityExceeded => {
                Err(ReasonCode::RequestCryptoReplayCapacityExceeded)
            }
        }
    }

    fn encrypt_response(
        &self,
        session: &Session,
        context: &mut RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        let Some(rule) = self
            .config
            .response_crypto_rule(request.method.as_str(), request.uri.path())
        else {
            return Ok(body);
        };
        let started_at = Instant::now();
        let result = (|| {
            let operation_id = context
                .decision
                .as_ref()
                .and_then(|decision| decision.operation_id.as_ref())
                .ok_or(ReasonCode::ResponseCryptoEncodingFailed)?;
            let status = context
                .origin_status
                .ok_or(ReasonCode::ResponseCryptoEncodingFailed)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| UnixSeconds::new(duration.as_secs()))
                .map_err(|_| ReasonCode::ClockUnavailable)?;
            let keys = self
                .response_key
                .as_ref()
                .ok_or(ReasonCode::ResponseCryptoKeyUnavailable)?;
            rule.encode(
                self.config.tenant_id().as_str(),
                self.config.site_id().as_str(),
                operation_id.as_str(),
                &context.request_id,
                request.method.as_str(),
                request.uri.path(),
                status,
                now,
                &body,
                keys,
            )
        })();
        match result {
            Ok(encrypted) => {
                context.response_crypto_audit = Some(ResponseCryptoAudit::passed(
                    encrypted.evidence(),
                    elapsed_us(started_at),
                ));
                Ok(encrypted.into_body())
            }
            Err(reason) => {
                context.response_crypto_audit = Some(ResponseCryptoAudit::failed(
                    rule,
                    reason,
                    elapsed_us(started_at),
                ));
                Err(reason)
            }
        }
    }

    fn commit_auth_binding(
        &self,
        session: &Session,
        context: &mut RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let Some(pending) = context.pending_auth_binding.take() else {
            return Ok(body);
        };
        let request = session.req_header();
        let rule = self
            .config
            .auth_binding_rule(request.method.as_str(), request.uri.path())
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let identity = self
            .identity
            .as_ref()
            .ok_or(ReasonCode::IdentityStoreUnavailable)?;
        let request_id = RequestId::parse(&context.request_id)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        // ponytail: Pingora 0.9 exposes a synchronous body filter; move this
        // barrier to an async body hook when the proxy API provides one.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(identity.commit_auth_binding(
                &self.config,
                rule,
                &pending,
                &request_id,
                &body,
            ))
        })?;
        Ok(body)
    }

    fn commit_response_grants(
        &self,
        session: &Session,
        context: &RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        let Some(operation) = self
            .config
            .response_grant_operation(request.method.as_str(), request.uri.path())
        else {
            return Ok(body);
        };
        let identity = self
            .identity
            .as_ref()
            .ok_or(ReasonCode::GrantSourceIneligible)?;
        let response_identity = context
            .response_identity
            .as_ref()
            .ok_or(ReasonCode::GrantSourceIneligible)?;
        let source_operation_id = context
            .decision
            .as_ref()
            .and_then(|decision| decision.operation_id.as_ref())
            .ok_or(ReasonCode::GrantSourceIneligible)?;
        let request_id = RequestId::parse(&context.request_id)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let response_status = context
            .origin_status
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| UnixSeconds::new(duration.as_secs()))
            .map_err(|_| ReasonCode::ClockUnavailable)?;
        // ponytail: Pingora 0.9 exposes a synchronous body filter; move this
        // barrier to an async body hook when the proxy API provides one.
        let action_refs = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(identity.commit_response_grants(
                &self.config,
                response_identity,
                operation,
                &request_id,
                source_operation_id,
                response_status,
                &body,
                now,
            ))
        })?;
        let Some(action_refs) = action_refs else {
            return Ok(body);
        };
        operation
            .rule
            .inject_action_refs(&body, &action_refs)
            .map(Bytes::from)
            .map_err(xshield_gateway::response_grant::ResponseGrantError::reason_code)
    }

    fn commit_auth_transition(
        &self,
        session: &Session,
        context: &RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        let refresh = self
            .config
            .auth_refresh_rule(request.method.as_str(), request.uri.path());
        let context_switch = self
            .config
            .auth_context_switch_rule(request.method.as_str(), request.uri.path());
        let Some(rule) = refresh.or(context_switch) else {
            return Ok(body);
        };
        let status = context
            .origin_status
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        if !rule.applies(status) {
            return Ok(body);
        }
        let identity = self
            .identity
            .as_ref()
            .ok_or(ReasonCode::IdentityStoreUnavailable)?;
        let response_identity = context
            .response_identity
            .as_ref()
            .ok_or(ReasonCode::AuthBindingMismatch)?;
        let request_id = RequestId::parse(&context.request_id)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| UnixSeconds::new(duration.as_secs()))
            .map_err(|_| ReasonCode::ClockUnavailable)?;
        // ponytail: Pingora 0.9 exposes a synchronous body filter; move this
        // barrier to an async body hook when the proxy API provides one.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                if context_switch.is_some() {
                    identity
                        .commit_auth_context_switch(
                            rule,
                            response_identity,
                            &request_id,
                            &body,
                            now,
                        )
                        .await
                } else {
                    identity
                        .commit_auth_refresh(rule, response_identity, &request_id, &body, now)
                        .await
                }
            })
        })?;
        Ok(body)
    }
}

fn prepare_grant_response_headers(response: &mut ResponseHeader) -> PingoraResult<()> {
    for name in [
        "Content-Length",
        "ETag",
        "Last-Modified",
        "Content-MD5",
        "Digest",
        "Content-Digest",
        "Repr-Digest",
        "Accept-Ranges",
        "Content-Range",
        "Trailer",
    ] {
        response.remove_header(name);
    }
    response.insert_header("Transfer-Encoding", "chunked")?;
    response.insert_header("Cache-Control", "private, no-store")
}

fn prepare_encrypted_response_headers(response: &mut ResponseHeader) -> PingoraResult<()> {
    for name in [
        "Content-Length",
        "Content-Encoding",
        "ETag",
        "Last-Modified",
        "Content-MD5",
        "Digest",
        "Content-Digest",
        "Repr-Digest",
        "Accept-Ranges",
        "Content-Range",
        "Trailer",
    ] {
        response.remove_header(name);
    }
    response.insert_header("Content-Type", ENCRYPTED_RESPONSE_CONTENT_TYPE)?;
    response.insert_header("Transfer-Encoding", "chunked")?;
    response.insert_header("Cache-Control", "private, no-store")
}

fn prepare_auth_response_headers(response: &mut ResponseHeader) -> PingoraResult<()> {
    for name in ["ETag", "Last-Modified", "Accept-Ranges", "Content-Range"] {
        response.remove_header(name);
    }
    response.insert_header("Cache-Control", "private, no-store")?;
    response.insert_header("Pragma", "no-cache")
}

fn append_waf_cookie(response: &mut ResponseHeader, value: &str) -> PingoraResult<()> {
    for header in response.headers.get_all("set-cookie") {
        let Ok(header) = header.to_str() else {
            return response_error(ReasonCode::ResponseValidationFailed);
        };
        let pair = header.split_once(';').map_or(header, |(pair, _)| pair);
        if pair
            .split_once('=')
            .is_some_and(|(name, _)| name.trim() == WAF_COOKIE)
        {
            return response_error(ReasonCode::ResponseValidationFailed);
        }
    }
    response.append_header("Set-Cookie", value).map(drop)
}

fn system_time() -> Result<UnixSeconds, Box<PingoraError>> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| UnixSeconds::new(duration.as_secs()))
        .map_err(|_| {
            PingoraError::explain(
                ErrorType::HTTPStatus(502),
                ReasonCode::ClockUnavailable.as_str(),
            )
        })
}

fn filter_response_trailers(
    buffered: bool,
    trailers: &mut http::HeaderMap,
) -> Result<(), ReasonCode> {
    if !buffered {
        return Ok(());
    }
    trailers.clear();
    Err(ReasonCode::ResponseValidationFailed)
}

fn response_error<T>(reason: ReasonCode) -> PingoraResult<T> {
    Err(PingoraError::explain(
        ErrorType::HTTPStatus(502),
        reason.as_str(),
    ))
}

fn request_error<T>(reason: ReasonCode) -> PingoraResult<T> {
    Err(PingoraError::explain(
        ErrorType::HTTPStatus(400),
        reason.as_str(),
    ))
}

fn elapsed_us(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX)
}

const fn denial_status(reason: ReasonCode) -> u16 {
    match reason {
        ReasonCode::AuthRequired => 401,
        ReasonCode::AnonymousSessionRateExceeded => 429,
        ReasonCode::RequestBodyTooLarge => 413,
        ReasonCode::AnonymousSessionCapacityExceeded
        | ReasonCode::IdentityStoreUnavailable
        | ReasonCode::RequestBufferCapacityExhausted
        | ReasonCode::RequestCryptoKeyUnavailable
        | ReasonCode::RequestCryptoReplayStoreUnavailable
        | ReasonCode::RequestCryptoReplayCapacityExceeded => 503,
        ReasonCode::RequestEnvelopeInvalid
        | ReasonCode::RequestCryptoAuthenticationFailed
        | ReasonCode::RequestCryptoMessageExpired
        | ReasonCode::RequestCryptoMessageFromFuture => 400,
        ReasonCode::RequestCryptoReplayDetected => 409,
        _ => 403,
    }
}

async fn respond_denial(
    session: &mut Session,
    status: u16,
    request_id: &str,
    reason: ReasonCode,
    session_cookie: Option<&str>,
) -> PingoraResult<()> {
    let body = denial_body(request_id, reason);
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header("Content-Type", "application/json")?;
    response.insert_header("Cache-Control", "private, no-store")?;
    response.insert_header("X-Xshield-Request-Id", request_id)?;
    if let Some(cookie) = session_cookie {
        response.append_header("Set-Cookie", cookie)?;
    }
    response.set_content_length(body.len())?;
    session
        .write_response_header(Box::new(response), false)
        .await?;
    session.write_response_body(Some(body), true).await
}

fn denial_body(request_id: &str, reason: ReasonCode) -> Bytes {
    let body = serde_json::json!({
        "error": "request_denied",
        "reason_code": reason.as_str(),
        "request_id": request_id,
    });
    Bytes::from(body.to_string())
}

fn load_config() -> Result<GatewayConfig, Box<dyn Error>> {
    let path = env::var("XSHIELD_CONFIG")?;
    let metadata = fs::metadata(&path)?;
    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err("gateway configuration exceeds size limit".into());
    }
    let bytes = fs::read(path)?;
    Ok(GatewayConfig::from_json(&bytes)?)
}

struct EnvRequestKey {
    tenant_id: String,
    site_id: String,
    key_id: String,
    key: Zeroizing<[u8; 32]>,
}

impl EnvRequestKey {
    fn from_env(config: &GatewayConfig) -> Result<Option<Self>, Box<dyn Error>> {
        let Some(key_id) = config.request_crypto_key_id() else {
            return Ok(None);
        };
        let value = Zeroizing::new(env::var("XSHIELD_REQUEST_DECRYPTION_KEY_HEX")?);
        let key = parse_crypto_key(&value).ok_or("invalid request decryption key")?;
        Ok(Some(Self {
            tenant_id: config.tenant_id().as_str().to_owned(),
            site_id: config.site_id().as_str().to_owned(),
            key_id: key_id.to_owned(),
            key: Zeroizing::new(key),
        }))
    }
}

impl KeyAccessPort for EnvRequestKey {
    fn request_decryption_key(
        &self,
        query: KeyAccessQuery<'_>,
    ) -> Result<Zeroizing<[u8; 32]>, ReasonCode> {
        if query.tenant_id != self.tenant_id
            || query.site_id != self.site_id
            || query.key_id != self.key_id
            || query.purpose != "request_direct_decrypt"
            || query.at == UnixSeconds::new(0)
        {
            return Err(ReasonCode::RequestCryptoKeyUnavailable);
        }
        Ok(Zeroizing::new(*self.key))
    }
}

struct EnvResponseKey {
    tenant_id: String,
    site_id: String,
    key_id: String,
    key: Zeroizing<[u8; 32]>,
}

impl EnvResponseKey {
    fn from_env(config: &GatewayConfig) -> Result<Option<Self>, Box<dyn Error>> {
        let Some(key_id) = config.response_crypto_key_id() else {
            return Ok(None);
        };
        let value = Zeroizing::new(env::var("XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX")?);
        let key = parse_crypto_key(&value).ok_or("invalid response encryption key")?;
        Ok(Some(Self {
            tenant_id: config.tenant_id().as_str().to_owned(),
            site_id: config.site_id().as_str().to_owned(),
            key_id: key_id.to_owned(),
            key: Zeroizing::new(key),
        }))
    }
}

impl ResponseKeyAccessPort for EnvResponseKey {
    fn response_encryption_key(
        &self,
        query: ResponseKeyAccessQuery<'_>,
    ) -> Result<Zeroizing<[u8; 32]>, ReasonCode> {
        if query.tenant_id != self.tenant_id
            || query.site_id != self.site_id
            || query.key_id != self.key_id
            || query.purpose != "response_direct_encrypt"
            || query.at == UnixSeconds::new(0)
        {
            return Err(ReasonCode::ResponseCryptoKeyUnavailable);
        }
        Ok(Zeroizing::new(*self.key))
    }
}

fn parse_crypto_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut key = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        key[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Some(key)
}

fn validate_encrypted_request_headers(
    request: &pingora::http::RequestHeader,
    max_bytes: usize,
) -> Result<(), ReasonCode> {
    if request.uri.query().is_some()
        || request
            .headers
            .get("Content-Type")
            .and_then(|value| value.to_str().ok())
            != Some(ENCRYPTED_REQUEST_CONTENT_TYPE)
        || request.headers.contains_key("Content-Encoding")
        || request.headers.contains_key("Trailer")
    {
        return Err(ReasonCode::RequestEnvelopeInvalid);
    }
    if let Some(length) = request.headers.get("Content-Length") {
        let length = length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(ReasonCode::RequestEnvelopeInvalid)?;
        if length > max_bytes {
            return Err(ReasonCode::RequestBodyTooLarge);
        }
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = Arc::new(load_config()?);
    let key_hex = Zeroizing::new(env::var("XSHIELD_JOURNAL_KEY_HEX")?);
    let audit = DurableAudit::open(&config, JournalKey::from_hex(&key_hex)?)?;
    let postgres = config
        .identity_store()
        .map(PostgresRuntime::from_env)
        .transpose()?
        .map(Arc::new);
    let identity = config
        .requires_identity_runtime()
        .then(|| {
            postgres
                .clone()
                .ok_or("identity store runtime unavailable")
                .and_then(|store| {
                    ProtectedIdentity::from_env(store).map_err(|_| "identity runtime unavailable")
                })
        })
        .transpose()?;
    let request_key = EnvRequestKey::from_env(&config)?;
    let response_key = EnvResponseKey::from_env(&config)?;
    if request_key
        .as_ref()
        .zip(response_key.as_ref())
        .is_some_and(|(request, response)| request.key.as_ref() == response.key.as_ref())
    {
        return Err("request and response encryption keys must differ".into());
    }
    let mut server = Server::new(None)?;
    server.bootstrap();
    let mut proxy = http_proxy_service(
        &server.configuration,
        Gateway {
            config: Arc::clone(&config),
            audit,
            identity,
            request_key,
            response_key,
            postgres,
            buffered_body_budget: Arc::new(Semaphore::new(MAX_BUFFERED_BODY_IN_FLIGHT_BYTES)),
        },
    );
    proxy.add_tcp(&config.listen().to_string());
    server.add_service(proxy);
    server.run_forever();
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xshield gateway startup failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_and_clears_trailers_for_buffered_responses() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("Digest", "sha-256=origin".parse().unwrap());
        assert_eq!(
            filter_response_trailers(true, &mut trailers),
            Err(ReasonCode::ResponseValidationFailed)
        );
        assert!(trailers.is_empty());
    }

    #[test]
    fn rejects_origin_collision_with_edge_session_cookie() {
        let mut response = ResponseHeader::build(200, Some(1)).unwrap();
        response
            .append_header("Set-Cookie", "__Host-xshield_sid=origin; Secure; Path=/")
            .unwrap();
        assert!(append_waf_cookie(&mut response, "edge=value").is_err());
    }

    #[test]
    fn maps_identity_denials_to_client_and_dependency_statuses() {
        assert_eq!(denial_status(ReasonCode::AuthRequired), 401);
        assert_eq!(denial_status(ReasonCode::AnonymousSessionRateExceeded), 429);
        assert_eq!(
            denial_status(ReasonCode::AnonymousSessionCapacityExceeded),
            503
        );
        assert_eq!(denial_status(ReasonCode::AuthBindingMismatch), 403);
    }
}
