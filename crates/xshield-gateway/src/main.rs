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
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use uuid::Uuid;
use xshield_audit::JournalKey;
use xshield_core::{audit::ReasonCode, identity::UnixSeconds};
use xshield_gateway::{GatewayConfig, GatewayDecision, GatewayOutcome, MAX_CONFIG_BYTES};
use zeroize::Zeroizing;

use crate::buffered_json::BufferedJsonResponse;
use crate::durable_audit::{
    AdmissionAudit, AdmissionFacts, DurableAudit, FinalFacts, new_trace_id,
};
use crate::protected_identity::{ProtectedIdentity, store_failure_reason, strip_edge_proofs};

const BUFFERED_JSON_IN_FLIGHT_BYTES: usize = 64 * 1024 * 1024;

struct Gateway {
    config: Arc<GatewayConfig>,
    audit: DurableAudit,
    identity: Option<ProtectedIdentity>,
    buffered_json_budget: Arc<Semaphore>,
}

struct RequestContext {
    request_id: String,
    trace_id: String,
    started_at: Instant,
    decision: Option<GatewayDecision>,
    admission_audit: Option<AdmissionAudit>,
    buffered_response: Option<BufferedJsonResponse>,
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
            buffered_response: None,
            response_failure: None,
            origin_status: None,
        }
    }

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
            )
            .await?;
            return Ok(true);
        }
        let request = session.req_header();
        let method = request.method.as_str().to_owned();
        let path = request.uri.path().to_owned();
        let Ok(wall_time) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            respond_denial(
                session,
                503,
                &context.request_id,
                ReasonCode::ClockUnavailable,
            )
            .await?;
            return Ok(true);
        };
        let now = UnixSeconds::new(wall_time.as_secs());
        let decision = match self.identity.as_ref() {
            Some(identity) => {
                if let Ok(decision) = identity
                    .admit(&self.config, request, &method, &path, now)
                    .await
                {
                    decision
                } else {
                    let mut decision = self.config.admit(&method, &path, now);
                    decision.outcome = GatewayOutcome::Denied;
                    decision.reason_code = store_failure_reason();
                    decision
                }
            }
            None => self.config.admit(&method, &path, now),
        };
        let audit_result = self
            .audit
            .commit_admission(AdmissionFacts {
                request_id: &context.request_id,
                trace_id: &context.trace_id,
                method: &method,
                decision: &decision,
                duration_us: elapsed_us(context.started_at),
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
                )
                .await?;
                return Ok(true);
            }
        };
        context.decision = Some(decision.clone());
        context.admission_audit = Some(admission_audit);
        if decision.outcome == GatewayOutcome::Denied {
            let status = if decision.reason_code == ReasonCode::IdentityStoreUnavailable {
                503
            } else {
                403
            };
            respond_denial(session, status, &context.request_id, decision.reason_code).await?;
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
        upstream_request.insert_header("Host", self.config.origin_server_name())?;
        upstream_request.insert_header("X-Xshield-Request-Id", &context.request_id)?;
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
        if upstream_response.status.as_u16() == 101 && buffered_json_limit.is_some() {
            context.origin_status = Some(101);
            context.response_failure = Some(ReasonCode::ResponseValidationFailed);
            return response_error(ReasonCode::ResponseValidationFailed);
        }
        if !upstream_response.status.is_informational() {
            context.origin_status = Some(upstream_response.status.as_u16());
            if let Some(limit) = buffered_json_limit {
                match BufferedJsonResponse::begin(
                    upstream_response,
                    limit,
                    &self.buffered_json_budget,
                ) {
                    Ok(buffer) => context.buffered_response = Some(buffer),
                    Err(reason) => {
                        context.response_failure = Some(reason);
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
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        context: &mut Self::CTX,
    ) -> PingoraResult<Option<std::time::Duration>> {
        let Some(buffer) = context.buffered_response.as_mut() else {
            return Ok(None);
        };
        if let Err(reason) = buffer.filter(body, end_of_stream) {
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
            })
            .await;
        if let Err(error) = result {
            self.audit.observe_failure(&error);
        }
    }
}

fn response_error<T>(reason: ReasonCode) -> PingoraResult<T> {
    Err(PingoraError::explain(
        ErrorType::HTTPStatus(502),
        reason.as_str(),
    ))
}

fn elapsed_us(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX)
}

async fn respond_denial(
    session: &mut Session,
    status: u16,
    request_id: &str,
    reason: ReasonCode,
) -> PingoraResult<()> {
    let body = denial_body(request_id, reason);
    let mut response = ResponseHeader::build(status, Some(4))?;
    response.insert_header("Content-Type", "application/json")?;
    response.insert_header("Cache-Control", "private, no-store")?;
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

fn run() -> Result<(), Box<dyn Error>> {
    let config = Arc::new(load_config()?);
    let key_hex = Zeroizing::new(env::var("XSHIELD_JOURNAL_KEY_HEX")?);
    let audit = DurableAudit::open(&config, JournalKey::from_hex(&key_hex)?)?;
    let identity = config
        .identity_store()
        .map(ProtectedIdentity::from_env)
        .transpose()?;
    let mut server = Server::new(None)?;
    server.bootstrap();
    let mut proxy = http_proxy_service(
        &server.configuration,
        Gateway {
            config: Arc::clone(&config),
            audit,
            identity,
            buffered_json_budget: Arc::new(Semaphore::new(BUFFERED_JSON_IN_FLIGHT_BYTES)),
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
