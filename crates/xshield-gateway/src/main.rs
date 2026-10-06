mod apply_api;
mod buffered_json;
mod descriptor_supply;
mod durable_audit;
mod edge_health;
mod evidence_writer;
mod listener_supervisor;
mod protected_identity;
mod rate_limit;
mod sensor_delivery;
mod unrouted;

use crate::listener_supervisor::ListenerSupervisor;
use crate::rate_limit::SiteRateLimiter;
use crate::unrouted::{FLUSH_INTERVAL, UnroutedDenials, flush_unrouted_denials};
use async_trait::async_trait;
use bytes::Bytes;
use pingora::{
    Error as PingoraError, ErrorType, Result as PingoraResult,
    http::ResponseHeader,
    proxy::{ProxyHttp, Session},
    server::Server,
    upstreams::peer::HttpPeer,
};
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use xshield_core::{audit::ReasonCode, domain::RequestId, identity::UnixSeconds};
use xshield_gateway::edge_transport::{EdgeTransport, TransportConfig, http_server_options};
use xshield_gateway::multi_site::{
    ApplyCoordinator, ConfigSnapshotStore, GatewaySite, GatewaySnapshot, frozen_origin_target,
    origin_form_target, routing_authority,
};
use xshield_gateway::request_crypto::{
    FrozenRequest, KeyAccessPort, KeyAccessQuery, RequestCryptoPolicy,
};
use xshield_gateway::response_crypto::{
    ENCRYPTED_RESPONSE_CONTENT_TYPE, ResponseKeyAccessPort, ResponseKeyAccessQuery,
};
use xshield_gateway::sensor::{MAX_SENSOR_OBSERVATION_BYTES, SensorObservationBatch};
use xshield_gateway::{
    BufferedResponsePolicy, GatewayConfig, GatewayDecision, GatewayOutcome, InternalResponse,
    MAX_BUFFERED_BODY_IN_FLIGHT_BYTES, MAX_BUFFERED_JSON_BYTES, MAX_CONFIG_BYTES,
};
use xshield_postgres::{
    PostgresIdentityStore, RequestCryptoMessage, RequestCryptoMessageOutcome, SensorSession,
    StoreError,
};
use zeroize::Zeroizing;

use crate::buffered_json::BufferedResponse;
use crate::descriptor_supply::{DescriptorStore, StartupSource, supply_before_serving};
use crate::durable_audit::{
    AdmissionAudit, AdmissionFacts, DurableAudit, FinalFacts, PageActionAudit, RecoveryBackoff,
    RequestCryptoAudit, ResponseCryptoAudit, ResponseSource, SensorBootstrapAudit, SensorHtmlAudit,
    SensorObservationAudit, new_trace_id, supervise_recovery,
};
use crate::protected_identity::{
    CompatibilityEvidence, PendingAuthBinding, ProtectedIdentity, ResponseIdentity,
    SensorBootstrapDelivery, WAF_COOKIE, store_failure_reason, strip_edge_proofs,
};
use crate::sensor_delivery::{
    SensorScript, bootstrap_document, respond_sensor_bootstrap, respond_sensor_script,
};

const ENCRYPTED_REQUEST_CONTENT_TYPE: &str = "application/vnd.xshield.encrypted+json";

fn validate_sensor_observation_headers(
    request: &pingora::http::RequestHeader,
    expected_origin: &str,
) -> Result<usize, ReasonCode> {
    if request.uri.query().is_some()
        || request.headers.contains_key("Content-Encoding")
        || request.headers.contains_key("Transfer-Encoding")
        || request.headers.contains_key("Trailer")
    {
        return Err(ReasonCode::SensorObservationInvalid);
    }
    let mut origins = request.headers.get_all("Origin").iter();
    if origins.next().and_then(|value| value.to_str().ok()) != Some(expected_origin)
        || origins.next().is_some()
    {
        return Err(ReasonCode::SensorObservationInvalid);
    }
    let mut content_types = request.headers.get_all("Content-Type").iter();
    if content_types.next().and_then(|value| value.to_str().ok()) != Some("application/json")
        || content_types.next().is_some()
    {
        return Err(ReasonCode::SensorObservationInvalid);
    }
    let mut lengths = request.headers.get_all("Content-Length").iter();
    let length = lengths
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| (1..=MAX_SENSOR_OBSERVATION_BYTES).contains(length))
        .ok_or(ReasonCode::SensorObservationInvalid)?;
    if lengths.next().is_some() {
        return Err(ReasonCode::SensorObservationInvalid);
    }
    Ok(length)
}

struct Gateway {
    config: Arc<GatewayConfig>,
    snapshot: Arc<ConfigSnapshotStore>,
    audit: DurableAudit,
    identity: Option<ProtectedIdentity>,
    request_key: Option<EnvRequestKey>,
    response_key: Option<EnvResponseKey>,
    postgres: Option<Arc<PostgresRuntime>>,
    buffered_body_budget: Arc<Semaphore>,
    evidence: Option<evidence_writer::EvidenceWriter>,
    rate_limiter: Arc<SiteRateLimiter>,
    unrouted: Arc<UnroutedDenials>,
}

struct PostgresRuntime {
    database_url: Zeroizing<String>,
    max_connections: u32,
    acquire_timeout: Duration,
    store: tokio::sync::OnceCell<PostgresIdentityStore>,
}

impl PostgresRuntime {
    fn from_env(config: xshield_gateway::IdentityStoreConfig) -> Result<Self, env::VarError> {
        Ok(Self::new(
            Zeroizing::new(env::var("XSHIELD_DATABASE_URL")?),
            config.max_connections(),
            Duration::from_millis(config.acquire_timeout_ms()),
        ))
    }

    /// A runtime that connects lazily, on first use, so building it never
    /// touches the network: an unreachable database fails whatever first
    /// needs it (a request, an apply, or a startup descriptor supply), and a
    /// failed connection is retried by the next caller.
    fn new(
        database_url: Zeroizing<String>,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Self {
        Self {
            database_url,
            max_connections,
            acquire_timeout,
            store: tokio::sync::OnceCell::new(),
        }
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
    request_body_len: usize,
    response_body_len: usize,
    request_crypto_audit: Option<RequestCryptoAudit>,
    response_crypto_audit: Option<ResponseCryptoAudit>,
    sensor_html_audit: Option<SensorHtmlAudit>,
    buffered_response: Option<BufferedResponse>,
    response_identity: Option<ResponseIdentity>,
    compatibility_evidence: Option<CompatibilityEvidence>,
    frozen_query: Option<xshield_gateway::FrozenQuery>,
    sensor_session: Option<SensorSession>,
    sensor_observation_audit: Vec<SensorObservationAudit>,
    sensor_bootstrap: Option<SensorBootstrapDelivery>,
    sensor_bootstrap_audit: Option<SensorBootstrapAudit>,
    page_action_audit: Option<PageActionAudit>,
    anonymous_session_cookie: Option<String>,
    pending_auth_binding: Option<PendingAuthBinding>,
    response_failure: Option<ReasonCode>,
    origin_status: Option<u16>,
    origin_response_complete: bool,
    response_source: ResponseSource,
    snapshot: Option<Arc<GatewaySnapshot>>,
    listener_port: Option<u16>,
    host: Option<String>,
    audit: Option<DurableAudit>,
}

impl RequestContext {
    fn config<'a>(&'a self, gateway: &'a Gateway) -> &'a GatewayConfig {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| {
                snapshot.route(
                    self.listener_port.unwrap_or(gateway.config.listen().port()),
                    self.host.as_deref().unwrap_or_default(),
                )
            })
            .unwrap_or(&gateway.config)
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
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
            request_body_len: 0,
            response_body_len: 0,
            request_crypto_audit: None,
            response_crypto_audit: None,
            sensor_html_audit: None,
            buffered_response: None,
            response_identity: None,
            compatibility_evidence: None,
            frozen_query: None,
            sensor_session: None,
            sensor_observation_audit: Vec::new(),
            sensor_bootstrap: None,
            sensor_bootstrap_audit: None,
            page_action_audit: None,
            anonymous_session_cookie: None,
            pending_auth_binding: None,
            response_failure: None,
            origin_status: None,
            origin_response_complete: false,
            response_source: ResponseSource::Origin,
            snapshot: None,
            // Known once request_filter reads the connection's socket digest.
            listener_port: None,
            host: None,
            audit: None,
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
        // The edge transport writes the attributed client (the PROXY source
        // from a trusted balancer, else the TCP peer) and the listener address
        // into the connection's socket digest, for HTTP/1 and HTTP/2 alike.
        let client_ip = session
            .as_downstream()
            .client_addr()
            .and_then(|address| address.as_inet())
            .map(std::net::SocketAddr::ip);
        let listener_port = session
            .as_downstream()
            .server_addr()
            .and_then(|address| address.as_inet().map(std::net::SocketAddr::port))
            .unwrap_or_else(|| context.config(self).listen().port());
        let request = session.req_header();
        let method = request.method.as_str().to_owned();
        let path = request.uri.path().to_owned();
        // Host and the HTTP/2 :authority or HTTP/1 absolute-form authority
        // must agree; an ambiguous request has no site and is refused below
        // exactly like an unknown Host.
        let authority = routing_authority(request);
        let host = authority.ok().flatten().map(str::to_owned);
        let snapshot = self.snapshot.load();
        if authority.is_err()
            || snapshot
                .route(listener_port, host.as_deref().unwrap_or_default())
                .is_none()
        {
            // No site owns this request, so it cannot be audited under one and
            // a durable event per request would let a flood fill the journal.
            // Count it; one bounded summary per port and interval is written.
            self.unrouted.record(
                listener_port,
                host.as_deref(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(1, |elapsed| elapsed.as_secs().max(1)),
            );
            respond_denial(
                session,
                503,
                &context.request_id,
                ReasonCode::SiteConfigUnavailable,
                None,
            )
            .await?;
            return Ok(true);
        }
        context.snapshot = Some(snapshot);
        context.listener_port = Some(listener_port);
        context.host = host;
        let snapshot_for_audit = context.snapshot.clone();
        let selected_config = snapshot_for_audit
            .as_ref()
            .and_then(|snapshot| {
                snapshot.route(listener_port, context.host.as_deref().unwrap_or_default())
            })
            .unwrap_or(&self.config);
        context.audit = Some(self.audit.scoped(selected_config));
        let internal_response = selected_config.internal_response(&method, &path);
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
        let pre_admission_denial = selected_config.site_policy().and_then(|policy| {
            pre_admission_denial(
                &self.rate_limiter,
                selected_config.site_id().as_str(),
                client_ip,
                policy,
                request,
            )
        });
        let mut decision = if let Some(reason) = pre_admission_denial {
            let mut decision = selected_config.admit(&method, &path, now);
            decision.outcome = GatewayOutcome::Denied;
            decision.reason_code = reason;
            decision
        } else {
            match self.identity.as_ref() {
                Some(identity) => {
                    if let Ok(admission) = identity
                        .admit(
                            selected_config,
                            request,
                            &request_id,
                            &context.trace_id,
                            client_ip,
                            now,
                        )
                        .await
                    {
                        context.response_identity = admission.response_identity;
                        context.anonymous_session_cookie = admission.anonymous_session_cookie;
                        context.compatibility_evidence = admission.compatibility_evidence;
                        context.frozen_query = admission.frozen_query;
                        context.sensor_session = admission.sensor_session;
                        context.sensor_bootstrap_audit = match &admission.sensor_bootstrap {
                            Some(SensorBootstrapDelivery::Page { actions, .. }) => {
                                Some(SensorBootstrapAudit::new(actions.len()))
                            }
                            Some(SensorBootstrapDelivery::Legacy) | None => None,
                        };
                        context.sensor_bootstrap = admission.sensor_bootstrap;
                        admission.decision
                    } else {
                        let mut decision = selected_config.admit(&method, &path, now);
                        decision.outcome = GatewayOutcome::Denied;
                        decision.reason_code = store_failure_reason();
                        decision
                    }
                }
                None => selected_config.admit(&method, &path, now),
            }
        };
        if request
            .headers
            .get("Content-Length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > selected_config.request_body_limit())
        {
            decision.outcome = GatewayOutcome::Denied;
            decision.reason_code = ReasonCode::RequestBodyTooLarge;
        }
        self.apply_sensor_observation(session, context, internal_response, &mut decision)
            .await;
        self.apply_request_crypto(session, context, &method, &path, now, &mut decision)
            .await;
        let audit_result = context
            .audit
            .as_ref()
            .unwrap_or(&self.audit)
            .commit_admission(AdmissionFacts {
                request_id: &context.request_id,
                trace_id: &context.trace_id,
                method: &method,
                decision: &decision,
                duration_us: elapsed_us(context.started_at),
                request_crypto: context.request_crypto_audit.as_ref(),
                sensor_observations: &context.sensor_observation_audit,
                sensor_bootstrap: context.sensor_bootstrap_audit.as_ref(),
                forward_origin: internal_response.is_none(),
            })
            .await;
        let admission_audit = match audit_result {
            Ok(receipt) => receipt,
            Err(error) => {
                context
                    .audit
                    .as_ref()
                    .unwrap_or(&self.audit)
                    .observe_failure(&error);
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
        if let Some(internal_response) = internal_response {
            context.response_source = ResponseSource::Edge;
            match internal_response {
                InternalResponse::SensorAsset => {
                    respond_sensor_script(session, &context.request_id, SensorScript::CURRENT)
                        .await?;
                }
                InternalResponse::SensorLoader => {
                    respond_sensor_script(session, &context.request_id, SensorScript::LOADER)
                        .await?;
                }
                InternalResponse::LegacySensorAsset => {
                    respond_sensor_script(session, &context.request_id, SensorScript::LEGACY)
                        .await?;
                }
                InternalResponse::LegacySensorLoader => {
                    respond_sensor_script(
                        session,
                        &context.request_id,
                        SensorScript::LEGACY_LOADER,
                    )
                    .await?;
                }
                InternalResponse::SensorBootstrap => {
                    let config = context.config(self);
                    let sensor = config.sensor().ok_or_else(|| {
                        PingoraError::explain(
                            ErrorType::HTTPStatus(500),
                            "sensor bootstrap policy missing",
                        )
                    })?;
                    let body = bootstrap_document(
                        &context.request_id,
                        sensor,
                        config.sensor_routes(),
                        context.sensor_bootstrap.as_ref(),
                        now,
                    );
                    respond_sensor_bootstrap(session, &context.request_id, body).await?;
                }
                InternalResponse::SensorPrepare => {
                    respond_sensor_observation(session, &context.request_id).await?;
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        context: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            context.config(self).origin_address(),
            context.config(self).origin_tls(),
            context.config(self).origin_server_name().to_owned(),
        )))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        context: &mut Self::CTX,
    ) -> PingoraResult<()> {
        strip_edge_proofs(upstream_request)?;
        // This header is edge-generated from the signed site policy.  Any
        // client supplied copy is removed so callers cannot opt out of the
        // origin's object ownership check.
        upstream_request.remove_header("X-Xshield-Object-Access");
        if context
            .config(self)
            .site_policy()
            .is_some_and(|policy| policy.origin_object_access_enforced)
        {
            upstream_request.insert_header("X-Xshield-Object-Access", "enforce")?;
        }
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
        // The origin always receives an origin-form target and its configured
        // Host. An HTTP/2 request or an HTTP/1 absolute-form target would
        // otherwise reach it as an absolute URI carrying the client's scheme.
        // A non-UTF-8 target is left for Pingora, which refuses to rewrite it.
        if upstream_request.raw_path_is_utf8()
            && let Some(target) = origin_form_target(upstream_request)
        {
            upstream_request.set_uri(target);
        }
        // A route that declared pagination parameters forwards only the query
        // the edge rebuilt from validated values; the client's raw query
        // string (its spelling, order and any byte outside the digits) never
        // reaches the origin. A target that cannot be rebuilt is refused.
        if let Some(frozen) = context.frozen_query.as_ref() {
            let Some(target) = frozen_origin_target(upstream_request.uri.path(), frozen.as_deref())
            else {
                return request_error(ReasonCode::FieldNotAllowed);
            };
            upstream_request.set_uri(target);
        }
        upstream_request.insert_header("Host", context.config(self).origin_server_name())?;
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
            if let Some(chunk) = body.as_ref() {
                context.request_body_len = context.request_body_len.saturating_add(chunk.len());
                if context.request_body_len > context.config(self).request_body_limit() {
                    return request_error(ReasonCode::RequestBodyTooLarge);
                }
            }
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
        let response_limit = context
            .config(self)
            .site_policy()
            .map_or(MAX_BUFFERED_JSON_BYTES, |policy| {
                policy.limits.max_response_body_bytes
            });
        if upstream_response
            .headers
            .get("Content-Length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > response_limit)
        {
            context.response_failure = Some(ReasonCode::ResponseBodyTooLarge);
            return response_error(ReasonCode::ResponseBodyTooLarge);
        }
        let has_buffered_policy = context
            .config(self)
            .buffered_response_policy(request.method.as_str(), request.uri.path())
            .is_some();
        if upstream_response.status.as_u16() == 101 && has_buffered_policy {
            context.origin_status = Some(101);
            context.response_failure = Some(ReasonCode::ResponseValidationFailed);
            if let Some(rule) = context
                .config(self)
                .response_crypto_rule(request.method.as_str(), request.uri.path())
            {
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
            if context
                .config(self)
                .response_share_operation(request.method.as_str(), request.uri.path())
                .is_some()
                && (upstream_response.headers.contains_key("Content-Range")
                    || upstream_response
                        .headers
                        .contains_key("Content-Disposition"))
            {
                context.response_failure = Some(ReasonCode::ResponseValidationFailed);
                return response_error(ReasonCode::ResponseValidationFailed);
            }
            let buffered = {
                let config = context.config(self);
                let Some(policy) =
                    config.buffered_response_policy(request.method.as_str(), request.uri.path())
                else {
                    return finish_response_header(upstream_response, &context.request_id);
                };
                let response_crypto_rule =
                    config.response_crypto_rule(request.method.as_str(), request.uri.path());
                let reservation_bytes = response_crypto_rule
                    .map(xshield_gateway::response_crypto::ResponseCryptoRule::max_in_flight_bytes)
                    .or_else(|| policy.max_in_flight_bytes())
                    .ok_or_else(|| {
                        PingoraError::explain(
                            ErrorType::HTTPStatus(502),
                            ReasonCode::ResponseBufferCapacityExhausted.as_str(),
                        )
                    })?;
                let encrypted = response_crypto_rule.is_some();
                let sensor_html = matches!(policy, BufferedResponsePolicy::SensorHtml(_));
                let buffer = BufferedResponse::begin(
                    upstream_response,
                    policy,
                    reservation_bytes,
                    &self.buffered_body_budget,
                );
                (buffer, encrypted, sensor_html)
            };
            match buffered.0 {
                Ok(buffer) => {
                    self.prepare_response_issuance_headers(request, upstream_response, context)?;
                    if buffered.1 {
                        prepare_encrypted_response_headers(upstream_response)?;
                    } else if buffered.2 {
                        prepare_sensor_html_response_headers(upstream_response)?;
                    }
                    context.buffered_response = Some(buffer);
                }
                Err(reason) => {
                    context.response_failure = Some(reason);
                    if let Some(rule) = context
                        .config(self)
                        .response_crypto_rule(request.method.as_str(), request.uri.path())
                    {
                        context.response_crypto_audit =
                            Some(ResponseCryptoAudit::failed(rule, reason, 0));
                    }
                    return response_error(reason);
                }
            }
        }
        finish_response_header(upstream_response, &context.request_id)
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        context: &mut Self::CTX,
    ) -> PingoraResult<Option<std::time::Duration>> {
        if context.buffered_response.is_none() {
            if let Some(chunk) = body.as_ref() {
                context.response_body_len = context.response_body_len.saturating_add(chunk.len());
                let limit = context
                    .config(self)
                    .site_policy()
                    .map_or(MAX_BUFFERED_JSON_BYTES, |policy| {
                        policy.limits.max_response_body_bytes
                    });
                if context.response_body_len > limit {
                    context.response_failure = Some(ReasonCode::ResponseBodyTooLarge);
                    return response_error(ReasonCode::ResponseBodyTooLarge);
                }
            }
            return Ok(None);
        }
        let Some(buffer) = context.buffered_response.as_mut() else {
            return Ok(None);
        };
        match buffer.filter(body, end_of_stream) {
            Ok(Some(complete)) => {
                context.origin_response_complete = true;
                if let Some(transformation) = complete.sensor_html {
                    // Issuance never withholds the verified page: a failure is
                    // audited and the page simply holds no references.
                    context.page_action_audit = self.issue_page_actions(
                        session,
                        context,
                        &transformation.page_handle,
                        &transformation.origin_sha256,
                        &transformation.injected_sha256,
                    );
                    context.sensor_html_audit = Some(SensorHtmlAudit::new(
                        transformation.adapter_revision,
                        transformation.origin_sha256,
                        transformation.injected_sha256,
                        transformation.csp_nonce_applied,
                    ));
                }
                let released = self
                    .capture_response(session, context, complete.body)
                    .and_then(|body| self.commit_auth_binding(session, context, body))
                    .and_then(|body| self.commit_auth_transition(session, context, body))
                    .and_then(|body| self.commit_auth_revoke(session, context, body))
                    .and_then(|body| self.commit_response_grants(session, context, body))
                    .and_then(|body| self.commit_response_share(session, context, body))
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
                if let Some(rule) = context
                    .config(self)
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
        let result = context
            .audit
            .as_ref()
            .unwrap_or(&self.audit)
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
                origin_response_complete: context.origin_response_complete,
                response_crypto: context.response_crypto_audit.as_ref(),
                sensor_html: context.sensor_html_audit.as_ref(),
                page_actions: context.page_action_audit.as_ref(),
                response_source: context.response_source,
            })
            .await;
        if let Err(error) = result {
            context
                .audit
                .as_ref()
                .unwrap_or(&self.audit)
                .observe_failure(&error);
        }
    }
}

impl Gateway {
    // Pingora fixes headers before the body commit barrier. Keep issuance-only
    // cache and cookie preparation together across all response issuers.
    fn prepare_response_issuance_headers(
        &self,
        request: &pingora::http::RequestHeader,
        upstream_response: &mut ResponseHeader,
        context: &mut RequestContext,
    ) -> PingoraResult<()> {
        if let Some(rule) = context
            .config(self)
            .auth_binding_rule(request.method.as_str(), request.uri.path())
        {
            prepare_auth_response_headers(upstream_response)?;
            if rule.applies(upstream_response.status.as_u16()) {
                let now = system_time()?;
                let pending =
                    ProtectedIdentity::prepare_auth_binding(rule, now).map_err(|reason| {
                        PingoraError::explain(ErrorType::HTTPStatus(502), reason.as_str())
                    })?;
                // Pingora fixes response headers before its synchronous body
                // filter runs. This cookie names only an unbound session until
                // the buffered authentication body commits successfully.
                append_waf_cookie(upstream_response, &pending.cookie_header_value())?;
                context.pending_auth_binding = Some(pending);
            }
        } else if context
            .config(self)
            .auth_refresh_rule(request.method.as_str(), request.uri.path())
            .is_some()
            || context
                .config(self)
                .auth_context_switch_rule(request.method.as_str(), request.uri.path())
                .is_some()
            || context
                .config(self)
                .auth_revoke_rule(request.method.as_str(), request.uri.path())
                .is_some()
        {
            prepare_auth_response_headers(upstream_response)?;
        } else if context
            .config(self)
            .response_grant_operation(request.method.as_str(), request.uri.path())
            .is_some()
            || context
                .config(self)
                .response_share_operation(request.method.as_str(), request.uri.path())
                .is_some()
        {
            prepare_grant_response_headers(upstream_response)?;
        }
        Ok(())
    }

    fn capture_response(
        &self,
        session: &Session,
        context: &mut RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        if context
            .config(self)
            .evidence_capture_rule(request.method.as_str(), request.uri.path())
            .is_none()
        {
            return Ok(body);
        }
        let writer = self
            .evidence
            .as_ref()
            .ok_or(ReasonCode::EvidenceCaptureUnavailable)?;
        let postgres = self
            .postgres
            .as_ref()
            .ok_or(ReasonCode::EvidenceCaptureUnavailable)?;
        let mut admission = context
            .admission_audit
            .take()
            .ok_or(ReasonCode::EvidenceCaptureUnavailable)?;
        let rule = context
            .config(self)
            .evidence_capture_rule(request.method.as_str(), request.uri.path())
            .ok_or(ReasonCode::EvidenceCaptureUnavailable)?;
        let result = writer.capture(
            context.config(self),
            postgres,
            context.audit.as_ref().unwrap_or(&self.audit),
            &context.request_id,
            &context.trace_id,
            &mut admission,
            rule,
            &body,
        );
        context.admission_audit = Some(admission);
        result?;
        Ok(body)
    }

    async fn apply_sensor_observation(
        &self,
        session: &mut Session,
        context: &mut RequestContext,
        internal_response: Option<InternalResponse>,
        decision: &mut GatewayDecision,
    ) {
        if internal_response != Some(InternalResponse::SensorPrepare)
            || decision.outcome != GatewayOutcome::Allowed
        {
            return;
        }
        let result = self.read_sensor_observation(session, context).await;
        match result {
            Ok(audit) => context.sensor_observation_audit = audit,
            Err(reason) => {
                decision.outcome = GatewayOutcome::Denied;
                decision.reason_code = reason;
            }
        }
    }

    async fn read_sensor_observation(
        &self,
        session: &mut Session,
        context: &RequestContext,
    ) -> Result<Vec<SensorObservationAudit>, ReasonCode> {
        let sensor = context
            .config(self)
            .sensor()
            .ok_or(ReasonCode::SensorObservationInvalid)?;
        let expected_len =
            validate_sensor_observation_headers(session.req_header(), sensor.origin())?;
        let permits = u32::try_from(MAX_SENSOR_OBSERVATION_BYTES)
            .map_err(|_| ReasonCode::RequestBufferCapacityExhausted)?;
        let _permit = Arc::clone(&self.buffered_body_budget)
            .try_acquire_many_owned(permits)
            .map_err(|_| ReasonCode::RequestBufferCapacityExhausted)?;
        let mut body = Vec::new();
        body.try_reserve_exact(expected_len)
            .map_err(|_| ReasonCode::RequestBufferCapacityExhausted)?;
        while let Some(chunk) = session
            .read_request_body()
            .await
            .map_err(|_| ReasonCode::SensorObservationInvalid)?
        {
            if body.len().saturating_add(chunk.len()) > expected_len {
                return Err(ReasonCode::SensorObservationInvalid);
            }
            body.extend_from_slice(&chunk);
        }
        if body.len() != expected_len {
            return Err(ReasonCode::SensorObservationInvalid);
        }
        let batch = SensorObservationBatch::from_json(
            &body,
            &xshield_gateway::ACCEPTED_SENSOR_VERSIONS,
            sensor.build_ref(),
        )
        .map_err(|_| ReasonCode::SensorObservationInvalid)?;
        let sensor_session = context
            .sensor_session
            .as_ref()
            .ok_or(ReasonCode::AuthBindingMismatch)?;
        Ok(batch
            .observations()
            .iter()
            .map(|observation| SensorObservationAudit::new(sensor_session, observation))
            .collect())
    }

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
        let Some(policy) = context.config(self).request_crypto_policy(method, path) else {
            return;
        };
        let rule = match policy {
            RequestCryptoPolicy::Observe(rule) => {
                context.request_crypto_audit = Some(RequestCryptoAudit::observed(rule));
                return;
            }
            RequestCryptoPolicy::Compatibility(rule) => {
                let started_at = Instant::now();
                let evidence = context.compatibility_evidence.as_ref();
                let result = if is_xshield_encrypted_content_type(session.req_header()) {
                    Err(ReasonCode::RequestEnvelopeInvalid)
                } else {
                    evidence
                        .ok_or(ReasonCode::RequestCryptoBuildNotApproved)
                        .and_then(|evidence| {
                            rule.authorize(now, &evidence.build_fingerprint)
                                .map(|()| evidence)
                        })
                };
                match result {
                    Ok(evidence) => {
                        context.request_crypto_audit = Some(RequestCryptoAudit::compatible(
                            rule,
                            &evidence.page_evidence_id,
                            elapsed_us(started_at),
                        ));
                    }
                    Err(reason) => {
                        context.request_crypto_audit =
                            Some(RequestCryptoAudit::compatibility_failed(
                                rule,
                                evidence.map(|value| &value.page_evidence_id),
                                reason,
                                elapsed_us(started_at),
                            ));
                        decision.outcome = GatewayOutcome::Denied;
                        decision.reason_code = reason;
                    }
                }
                return;
            }
            RequestCryptoPolicy::Enforce(rule) => rule,
        };
        let started_at = Instant::now();
        match self
            .decrypt_request(session, context, rule, now, decision, &context.request_id)
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
        context: &RequestContext,
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
            context.config(self).tenant_id().as_str(),
            context.config(self).site_id().as_str(),
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
            context.config(self).tenant_id(),
            context.config(self).site_id(),
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
            RequestCryptoMessageOutcome::Expired => Err(ReasonCode::RequestCryptoMessageExpired),
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
        let Some(rule) = context
            .config(self)
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
                context.config(self).tenant_id().as_str(),
                context.config(self).site_id().as_str(),
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
        let rule = context
            .config(self)
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
                context.config(self),
                rule,
                &pending,
                &request_id,
                &context.trace_id,
                &body,
            ))
        })?;
        Ok(body)
    }

    /// Issues the actions a verified page root declares, after the exact
    /// pinned document was injected and before its body is released. Returns
    /// the audit record; `None` when the operation issues no page actions.
    fn issue_page_actions(
        &self,
        session: &Session,
        context: &RequestContext,
        page_handle: &str,
        origin_sha256: &str,
        injected_sha256: &str,
    ) -> Option<PageActionAudit> {
        let request = session.req_header();
        let config = context.config(self);
        let plan = config.page_action_plan(request.method.as_str(), request.uri.path())?;
        let mapping = plan.mapping_revision().as_str();
        let result = (|| {
            let identity = self
                .identity
                .as_ref()
                .ok_or(ReasonCode::IdentityStoreUnavailable)?;
            let response_identity = context
                .response_identity
                .as_ref()
                .ok_or(ReasonCode::UiActionNotAvailable)?;
            let request_id = RequestId::parse(&context.request_id)
                .map_err(|_| ReasonCode::UiActionNotAvailable)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| UnixSeconds::new(duration.as_secs()))
                .map_err(|_| ReasonCode::ClockUnavailable)?;
            // ponytail: Pingora 0.9 exposes a synchronous body filter; move this
            // barrier to an async body hook when the proxy API provides one.
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(identity.issue_page_actions(
                    config,
                    response_identity,
                    plan,
                    &request_id,
                    &context.trace_id,
                    page_handle,
                    origin_sha256,
                    injected_sha256,
                    now,
                ))
            })
        })();
        Some(match result {
            Ok(_) => PageActionAudit::issued(ReasonCode::UiActionIssued, mapping),
            Err(reason) => PageActionAudit::failed(reason, mapping),
        })
    }

    fn commit_response_grants(
        &self,
        session: &Session,
        context: &RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        let Some(operation) = context
            .config(self)
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
                context.config(self),
                response_identity,
                operation,
                &request_id,
                &context.trace_id,
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

    fn commit_response_share(
        &self,
        session: &Session,
        context: &RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        let Some(operation) = context
            .config(self)
            .response_share_operation(request.method.as_str(), request.uri.path())
        else {
            return Ok(body);
        };
        let status = context
            .origin_status
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let max_bytes = context
            .config(self)
            .buffered_json_max_bytes(request.method.as_str(), request.uri.path())
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let Some(prepared) = operation.rule.prepare(status, &body, max_bytes)? else {
            return Ok(body);
        };
        // The complete output allocation and fixed token slot are checked before
        // any side effect; release the original body before the transaction.
        drop(body);
        let identity = self
            .identity
            .as_ref()
            .ok_or(ReasonCode::IdentityStoreUnavailable)?;
        let response_identity = context
            .response_identity
            .as_ref()
            .ok_or(ReasonCode::ShareSourceIneligible)?;
        let request_id = RequestId::parse(&context.request_id)
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| UnixSeconds::new(duration.as_secs()))
            .map_err(|_| ReasonCode::ClockUnavailable)?;
        // ponytail: Pingora 0.9 has a synchronous body filter; use an async body
        // hook when available, preserving this pre-release transaction barrier.
        let token = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(identity.commit_response_share(
                context.config(self),
                response_identity,
                operation,
                &request_id,
                &context.trace_id,
                now,
            ))
        })?;
        // Transfer ownership without a plaintext clone; erase our response
        // allocation when Pingora releases its last reference, including errors.
        prepared
            .finish(&token)
            .map(|body| Bytes::from_owner(Zeroizing::new(body)))
    }

    fn commit_auth_transition(
        &self,
        session: &Session,
        context: &RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        let refresh = context
            .config(self)
            .auth_refresh_rule(request.method.as_str(), request.uri.path());
        let context_switch = context
            .config(self)
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
                            context.config(self),
                            rule,
                            response_identity,
                            &request_id,
                            &context.trace_id,
                            &body,
                            now,
                        )
                        .await
                } else {
                    identity
                        .commit_auth_refresh(
                            context.config(self),
                            rule,
                            response_identity,
                            &request_id,
                            &context.trace_id,
                            &body,
                            now,
                        )
                        .await
                }
            })
        })?;
        Ok(body)
    }

    fn commit_auth_revoke(
        &self,
        session: &Session,
        context: &RequestContext,
        body: Bytes,
    ) -> Result<Bytes, ReasonCode> {
        let request = session.req_header();
        let Some(rule) = context
            .config(self)
            .auth_revoke_rule(request.method.as_str(), request.uri.path())
        else {
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
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(identity.commit_auth_revoke(
                context.config(self),
                rule,
                response_identity,
                &request_id,
                &context.trace_id,
                status,
                now,
            ))
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

fn finish_response_header(response: &mut ResponseHeader, request_id: &str) -> PingoraResult<()> {
    response.insert_header("X-Xshield-Request-Id", request_id)?;
    Ok(())
}

fn prepare_sensor_html_response_headers(response: &mut ResponseHeader) -> PingoraResult<()> {
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
        ReasonCode::AnonymousSessionRateExceeded | ReasonCode::SiteRateLimitExceeded => 429,
        ReasonCode::RequestBodyTooLarge | ReasonCode::WafCookieTooLarge => 413,
        ReasonCode::AnonymousSessionCapacityExceeded
        | ReasonCode::IdentityStoreUnavailable
        | ReasonCode::RequestBufferCapacityExhausted
        | ReasonCode::RequestCryptoKeyUnavailable
        | ReasonCode::RequestCryptoReplayStoreUnavailable
        | ReasonCode::RequestCryptoReplayCapacityExceeded => 503,
        ReasonCode::RequestEnvelopeInvalid
        | ReasonCode::WafQueryInvalid
        | ReasonCode::SensorBootstrapInvalid
        | ReasonCode::SensorObservationInvalid
        | ReasonCode::RequestCryptoAuthenticationFailed
        | ReasonCode::RequestCryptoMessageExpired
        | ReasonCode::RequestCryptoMessageFromFuture => 400,
        ReasonCode::RequestCryptoReplayDetected => 409,
        _ => 403,
    }
}

/// Cheap, identity-free checks that decide a request before any identity,
/// crypto or durable-audit work. Returns the stable denial reason, if any.
fn pre_admission_denial(
    limiter: &SiteRateLimiter,
    site_id: &str,
    source: Option<std::net::IpAddr>,
    policy: &xshield_core::SitePolicyConfig,
    request: &pingora::http::RequestHeader,
) -> Option<ReasonCode> {
    // Metering comes first so every request, WAF-denied ones included, costs
    // a token: each denial still commits a durable audit record, and an
    // unmetered flood of them would fill the journal.
    if !limiter.allow(site_id, source, policy) {
        return Some(ReasonCode::SiteRateLimitExceeded);
    }
    site_waf_denial(request, policy)
}

fn site_waf_denial(
    request: &pingora::http::RequestHeader,
    policy: &xshield_core::SitePolicyConfig,
) -> Option<ReasonCode> {
    if !policy.waf.enabled {
        return None;
    }
    if policy
        .waf
        .blocked_headers
        .iter()
        .any(|header| request.headers.contains_key(header))
    {
        return Some(ReasonCode::WafHeaderBlocked);
    }
    if !policy.waf.blocked_query_fragments.is_empty()
        && let Some(query) = request.uri.query()
    {
        let Some(decoded) = decode_waf_query(query) else {
            return Some(ReasonCode::WafQueryInvalid);
        };
        if policy
            .waf
            .blocked_query_fragments
            .iter()
            .any(|fragment| decoded.contains(&fragment.to_ascii_lowercase()))
        {
            return Some(ReasonCode::WafQueryBlocked);
        }
    }
    let cookie_bytes = request
        .headers
        .get_all("Cookie")
        .iter()
        .map(|value| value.as_bytes().len())
        .sum::<usize>();
    (cookie_bytes > policy.waf.max_cookie_bytes as usize).then_some(ReasonCode::WafCookieTooLarge)
}

// Decode once, exactly as the upstream's query parser would, before matching.
// Invalid escape sequences fail closed when this policy is enabled.
fn decode_waf_query(query: &str) -> Option<String> {
    if query.len() > 8_192 {
        return None;
    }
    let mut output = Vec::with_capacity(query.len());
    let bytes = query.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes.get(index + 1..index + 3)?;
            let digit = |byte: u8| {
                (byte as char)
                    .to_digit(16)
                    .and_then(|digit| u8::try_from(digit).ok())
            };
            output.push((digit(pair[0])? << 4) | digit(pair[1])?);
            index += 3;
        } else {
            output.push(if bytes[index] == b'+' {
                b' '
            } else {
                bytes[index]
            });
            index += 1;
        }
    }
    let decoded = String::from_utf8(output).ok()?;
    if decoded.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    Some(decoded.to_ascii_lowercase())
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

async fn respond_sensor_observation(session: &mut Session, request_id: &str) -> PingoraResult<()> {
    let body = Bytes::from(
        serde_json::json!({
            "status": "accepted",
            "request_id": request_id,
        })
        .to_string(),
    );
    let mut response = ResponseHeader::build(202, Some(6))?;
    response.insert_header("Content-Type", "application/json")?;
    response.insert_header("Cache-Control", "private, no-store")?;
    response.insert_header("Cross-Origin-Resource-Policy", "same-origin")?;
    response.insert_header("X-Content-Type-Options", "nosniff")?;
    response.insert_header("X-Xshield-Request-Id", request_id)?;
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
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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

fn is_xshield_encrypted_content_type(request: &pingora::http::RequestHeader) -> bool {
    request
        .headers
        .get("Content-Type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case(ENCRYPTED_REQUEST_CONTENT_TYPE)
        })
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<(), Box<dyn Error>> {
    let config = Arc::new(load_config()?);
    let snapshot_config = load_config()?;
    // Validated before anything binds or writes: a broken TLS or PROXY
    // configuration stops startup instead of serving plaintext.
    let transport = Arc::new(EdgeTransport::new(TransportConfig::from_lookup(|name| {
        env::var_os(name)
    })?));
    let apply_key = env::var("XSHIELD_EDGE_APPLY_KEY_HEX")
        .ok()
        .map(|value| apply_api::key_from_hex(&value).ok_or("invalid edge apply key"))
        .transpose()?;
    let snapshot_path = env::var_os("XSHIELD_EDGE_SNAPSHOT_PATH").map(PathBuf::from);
    let mut persisted = match (snapshot_path.as_deref(), apply_key.as_ref()) {
        (Some(path), Some(key)) => {
            apply_api::load_persisted_snapshot(path, key, config.tenant_id().as_str())?
        }
        (Some(_), None) => {
            return Err("XSHIELD_EDGE_SNAPSHOT_PATH requires XSHIELD_EDGE_APPLY_KEY_HEX".into());
        }
        (None, _) => None,
    };
    let mut listener_addresses = configured_listener_addresses(config.listen())?;
    if let Some((_, snapshot)) = persisted.as_ref() {
        for port in snapshot.listener_ports() {
            let address = SocketAddr::new(config.listen().ip(), port);
            if !listener_addresses.contains(&address) {
                listener_addresses.push(address);
            }
        }
        validate_listener_addresses(&listener_addresses)?;
    }
    if !listener_addresses
        .iter()
        .any(|address| address.port() == config.listen().port())
    {
        return Err("XSHIELD_EDGE_LISTEN_PORTS must include the bootstrap listener".into());
    }
    let mut public_hosts = env::var("XSHIELD_PUBLIC_HOSTS")
        .unwrap_or_else(|_| config.origin_server_name().to_owned())
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    // The development listener is loopback-only, so accepting its exact IP
    // Host keeps direct local probes compatible without widening public routes.
    if config.listen().ip().is_loopback() {
        let host = config.listen().ip().to_string();
        if !public_hosts.iter().any(|current| current == &host) {
            public_hosts.push(host);
        }
    }
    // A restored snapshot serves before any control-plane apply, so its
    // page-issuing sites need the same descriptor supply an apply performs.
    let restored = persisted.is_some();
    let initial_snapshot = if let Some((_, snapshot)) = persisted.take() {
        // The signed complete snapshot is the restart source of truth. The
        // static file remains the bootstrap fallback only when no snapshot is
        // configured yet.
        snapshot
    } else if env::var("XSHIELD_EDGE_BOOTSTRAP_ONLY").as_deref() == Ok("1") {
        // Bootstrap-only mode deliberately exposes no business route until a
        // signed control-plane snapshot arrives through /internal/v1/apply.
        GatewaySnapshot::compile_for_tenant(1, config.tenant_id().clone(), Vec::new())?
    } else {
        GatewaySnapshot::compile(1, vec![GatewaySite::new(snapshot_config, public_hosts)?])?
    };
    let coordinator = Arc::new(ApplyCoordinator::new(Arc::new(ConfigSnapshotStore::new(
        initial_snapshot,
    ))));
    let key_hex = Zeroizing::new(env::var("XSHIELD_JOURNAL_KEY_HEX")?);
    let audit = DurableAudit::open_recoverable(&config, &key_hex)?;
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
                    ProtectedIdentity::from_env(store, config.requires_share_issuance())
                        .map_err(|_| "identity runtime unavailable")
                })
        })
        .transpose()?;
    let request_key = EnvRequestKey::from_env(&config)?;
    let response_key = EnvResponseKey::from_env(&config)?;
    let evidence = evidence_writer::EvidenceWriter::from_env(&config)?;
    if request_key
        .as_ref()
        .zip(response_key.as_ref())
        .is_some_and(|(request, response)| request.key.as_ref() == response.key.as_ref())
    {
        return Err("request and response encryption keys must differ".into());
    }
    let audit_readiness = audit.readiness();
    let audit_recovery = audit.clone();
    let audit_unrouted = audit.clone();
    let unrouted = Arc::new(UnroutedDenials::default());
    let mut server = Server::new(None)?;
    server.bootstrap();
    let mut proxy = pingora::proxy::http_proxy(
        &server.configuration,
        Gateway {
            config: Arc::clone(&config),
            snapshot: coordinator.snapshot_store(),
            audit,
            identity,
            request_key,
            response_key,
            evidence,
            postgres: postgres.clone(),
            buffered_body_budget: Arc::new(Semaphore::new(MAX_BUFFERED_BODY_IN_FLIGHT_BYTES)),
            rate_limiter: Arc::new(SiteRateLimiter::new()),
            unrouted: Arc::clone(&unrouted),
        },
    );
    proxy.server_options = Some(http_server_options());
    let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;
    // A durability failure closes the admission barrier; this keeps it
    // recoverable (bounded backoff, fail-closed in between) without a restart.
    runtime.spawn(supervise_recovery(
        audit_recovery,
        RecoveryBackoff::PRODUCTION,
        shutdown.clone(),
    ));
    runtime.spawn(flush_unrouted_denials(
        audit_unrouted,
        unrouted,
        FLUSH_INTERVAL,
        shutdown.clone(),
    ));
    // Descriptors must exist, unchanged, before any listener can admit a page
    // root or a gated request against them; any refusal stops startup. The
    // bootstrap configuration and a restored snapshot get the same idempotent
    // supply an apply performs, and an edge without an identity store refuses
    // to serve a page-issuing configuration at all.
    let descriptor_store = postgres
        .clone()
        .map(|runtime| runtime as Arc<dyn DescriptorStore>);
    runtime.block_on(supply_before_serving(
        descriptor_store.as_deref(),
        [config.as_ref()],
        StartupSource::Bootstrap,
    ))?;
    if restored {
        let snapshot = coordinator.current();
        runtime.block_on(supply_before_serving(
            descriptor_store.as_deref(),
            snapshot.sites(),
            StartupSource::PersistedSnapshot,
        ))?;
    }
    let supervisor = runtime.block_on(ListenerSupervisor::new(
        Arc::clone(&coordinator),
        Arc::new(proxy),
        transport,
        config.listen().ip(),
        &listener_addresses,
        shutdown.clone(),
    ))?;
    if let Some(key) = apply_key {
        let listen: SocketAddr = env::var("XSHIELD_EDGE_APPLY_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:9553".to_owned())
            .parse()?;
        if !listen.ip().is_loopback() {
            return Err("edge apply listener must use loopback".into());
        }
        let apply_listener = runtime.block_on(tokio::net::TcpListener::bind(listen))?;
        let state = apply_api::ApplyState::new(
            Arc::new(supervisor),
            config.tenant_id().as_str().to_owned(),
            key,
            snapshot_path,
            audit_readiness,
            descriptor_store,
        );
        runtime.spawn(async move {
            if let Err(error) = apply_api::serve(apply_listener, state).await {
                eprintln!("xshield edge apply listener stopped: {error}");
            }
        });
    }
    // The supervisor owns all data-plane sockets and apply coordination. Keep
    // its runtime alive while the process waits for shutdown.
    let _runtime = runtime;
    let _shutdown_tx = shutdown_tx;
    server.run_forever();
}

fn configured_listener_addresses(default: SocketAddr) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    let addresses = if let Ok(value) = env::var("XSHIELD_EDGE_LISTEN_PORTS") {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::parse::<SocketAddr>)
            .collect::<Result<Vec<_>, _>>()?
    } else {
        vec![default]
    };
    if addresses.is_empty() {
        return Err("XSHIELD_EDGE_LISTEN_PORTS must contain one listener".into());
    }
    if addresses.iter().any(|address| address.ip() != default.ip()) {
        return Err("XSHIELD_EDGE_LISTEN_PORTS must use the bootstrap bind address".into());
    }
    validate_listener_addresses(&addresses)?;
    Ok(addresses)
}

fn validate_listener_addresses(addresses: &[SocketAddr]) -> Result<(), &'static str> {
    let mut ports = BTreeSet::new();
    for address in addresses {
        if xshield_core::site::PortNumber::parse(address.port()).is_err() {
            return Err("XSHIELD_EDGE_LISTEN_PORTS must use the internal listener pool");
        }
        let allowed = match address.ip() {
            std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
            std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
        };
        if !allowed || !ports.insert(address.port()) {
            return Err("XSHIELD_EDGE_LISTEN_PORTS must use unique loopback or private addresses");
        }
    }
    Ok(())
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

    // A malformed request is the client's mistake (400), an unknown or
    // unauthorized one is forbidden (403). Every sensor input the edge refuses
    // because of its shape belongs with the other malformed-input reasons; the
    // identity script once expected 400 here while the edge answered 403, and
    // nothing noticed because its failed assertion was ignored by bash 3.2.
    #[test]
    fn denial_status_separates_malformed_input_from_forbidden_requests() {
        for reason in [
            ReasonCode::RequestEnvelopeInvalid,
            ReasonCode::WafQueryInvalid,
            ReasonCode::SensorBootstrapInvalid,
            ReasonCode::SensorObservationInvalid,
            ReasonCode::RequestCryptoAuthenticationFailed,
            ReasonCode::RequestCryptoMessageExpired,
            ReasonCode::RequestCryptoMessageFromFuture,
        ] {
            assert_eq!(denial_status(reason), 400, "{}", reason.as_str());
        }
        assert_eq!(denial_status(ReasonCode::AuthRequired), 401);
        assert_eq!(denial_status(ReasonCode::RequestCryptoReplayDetected), 409);
        assert_eq!(denial_status(ReasonCode::RequestBodyTooLarge), 413);
        assert_eq!(denial_status(ReasonCode::SiteRateLimitExceeded), 429);
        assert_eq!(denial_status(ReasonCode::IdentityStoreUnavailable), 503);
        for reason in [
            ReasonCode::UiActionNotAvailable,
            ReasonCode::AuthBindingMismatch,
            ReasonCode::HostNotRouted,
        ] {
            assert_eq!(denial_status(reason), 403, "{}", reason.as_str());
        }
    }

    fn limited_policy(burst: u32) -> xshield_core::SitePolicyConfig {
        let mut policy = xshield_core::SitePolicyConfig::default();
        policy.limits.requests_per_second = 1;
        policy.limits.burst = burst;
        policy.waf.enabled = true;
        policy.waf.blocked_headers = vec!["x-attack".to_owned()];
        policy
    }

    fn request_with(attack: bool) -> pingora::http::RequestHeader {
        let mut request = pingora::http::RequestHeader::build("GET", b"/search", Some(1)).unwrap();
        if attack {
            request.insert_header("x-attack", "1").unwrap();
        }
        request
    }

    // Reviewer finding: WAF denials skipped the limiter, yet each one still
    // committed a durable audit record, so a flood of WAF-denied requests was
    // never metered. Every request now takes a token before the WAF runs.
    #[test]
    fn waf_denied_floods_are_metered_before_the_waf() {
        let limiter = SiteRateLimiter::new();
        let policy = limited_policy(3);
        let source = Some("203.0.113.9".parse().unwrap());
        let reasons: Vec<_> = (0..8)
            .map(|_| pre_admission_denial(&limiter, "site_a", source, &policy, &request_with(true)))
            .collect();
        let allowed = usize::try_from(policy.limits.burst).unwrap();
        for (index, reason) in reasons.iter().enumerate() {
            let expected = if index < allowed {
                ReasonCode::WafHeaderBlocked
            } else {
                ReasonCode::SiteRateLimitExceeded
            };
            assert_eq!(*reason, Some(expected), "request {index}");
        }
    }

    #[test]
    fn clean_requests_share_the_same_budget_as_denied_ones() {
        let limiter = SiteRateLimiter::new();
        let policy = limited_policy(2);
        let source = Some("203.0.113.9".parse().unwrap());
        let check = |attack| {
            pre_admission_denial(&limiter, "site_a", source, &policy, &request_with(attack))
        };
        assert_eq!(check(true), Some(ReasonCode::WafHeaderBlocked));
        assert_eq!(check(false), None);
        // The third request exceeds the burst whatever it looks like.
        assert_eq!(check(false), Some(ReasonCode::SiteRateLimitExceeded));
        assert_eq!(check(true), Some(ReasonCode::SiteRateLimitExceeded));
        // Another source and another site are unaffected.
        let other = Some("203.0.113.10".parse().unwrap());
        assert_eq!(
            pre_admission_denial(&limiter, "site_a", other, &policy, &request_with(false)),
            None
        );
        assert_eq!(
            pre_admission_denial(&limiter, "site_b", source, &policy, &request_with(false)),
            None
        );
        // An unknown source cannot be metered and is refused.
        assert_eq!(
            pre_admission_denial(&limiter, "site_a", None, &policy, &request_with(false)),
            Some(ReasonCode::SiteRateLimitExceeded)
        );
    }

    #[test]
    fn listener_addresses_are_private_and_unique() {
        assert!(
            validate_listener_addresses(&[
                "127.0.0.1:6100".parse().unwrap(),
                "10.0.0.2:6101".parse().unwrap(),
            ])
            .is_ok()
        );
        assert!(validate_listener_addresses(&["127.0.0.1:1024".parse().unwrap()]).is_err());
        assert!(validate_listener_addresses(&["0.0.0.0:6100".parse().unwrap()]).is_err());
        assert!(
            validate_listener_addresses(&[
                "127.0.0.1:6100".parse().unwrap(),
                "127.0.0.2:6100".parse().unwrap(),
            ])
            .is_err()
        );
    }

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

    #[test]
    fn site_waf_blocks_configured_headers_and_cookie_overflow() {
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(2)).unwrap();
        request.insert_header("X-Debug", "1").unwrap();
        request.insert_header("Cookie", "a=123456").unwrap();
        let mut policy = xshield_core::SitePolicyConfig::default();
        policy.waf.blocked_headers = vec!["x-debug".to_owned()];
        policy.waf.max_cookie_bytes = 4;
        assert_eq!(
            site_waf_denial(&request, &policy),
            Some(ReasonCode::WafHeaderBlocked)
        );
        policy.waf.blocked_headers.clear();
        assert_eq!(
            site_waf_denial(&request, &policy),
            Some(ReasonCode::WafCookieTooLarge)
        );
    }

    #[test]
    fn site_waf_query_rules_decode_once_and_fail_closed() {
        let mut policy = xshield_core::SitePolicyConfig::default();
        policy.waf.blocked_query_fragments = vec!["' or 1=1--".to_owned()];
        let request =
            pingora::http::RequestHeader::build("GET", b"/search?q=%27+OR+1%3D1--", Some(1))
                .unwrap();
        assert_eq!(
            site_waf_denial(&request, &policy),
            Some(ReasonCode::WafQueryBlocked)
        );
        let malformed =
            pingora::http::RequestHeader::build("GET", b"/search?q=%GG", Some(1)).unwrap();
        assert_eq!(
            site_waf_denial(&malformed, &policy),
            Some(ReasonCode::WafQueryInvalid)
        );
        let safe =
            pingora::http::RequestHeader::build("GET", b"/search?q=green+apple", Some(1)).unwrap();
        assert_eq!(site_waf_denial(&safe, &policy), None);
        assert_eq!(denial_status(ReasonCode::WafQueryInvalid), 400);
    }

    #[test]
    fn site_rate_limiter_enforces_burst_per_source() {
        let limiter = SiteRateLimiter::new();
        let mut policy = xshield_core::SitePolicyConfig::default();
        policy.limits.requests_per_second = 1;
        policy.limits.burst = 1;
        let source = Some("127.0.0.1".parse().unwrap());
        assert!(limiter.allow("site_a", source, &policy));
        assert!(!limiter.allow("site_a", source, &policy));
        assert!(limiter.allow("site_a", Some("127.0.0.2".parse().unwrap()), &policy));
    }
}
