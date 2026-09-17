use async_trait::async_trait;
use bytes::Bytes;
use pingora::{
    Result as PingoraResult,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
    upstreams::peer::HttpPeer,
};
use serde::Serialize;
use std::{
    env,
    error::Error,
    fs,
    io::{self, Write},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use xshield_core::{audit::ReasonCode, identity::UnixSeconds};
use xshield_gateway::{GatewayConfig, GatewayDecision, MAX_CONFIG_BYTES};

struct Gateway {
    config: Arc<GatewayConfig>,
}

struct RequestContext {
    request_id: String,
    decision: Option<GatewayDecision>,
}

#[derive(Serialize)]
struct DecisionLog<'a> {
    event_type: &'static str,
    request_id: &'a str,
    method: &'a str,
    terminal_state: &'static str,
    admission_outcome: &'static str,
    admission_reason_code: &'static str,
    origin_state: &'static str,
    status: u16,
    durability: &'static str,
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            request_id: format!("req_{}", Uuid::now_v7()),
            decision: None,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        context: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        let request = session.req_header();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(UnixSeconds::new(0), |duration| {
                UnixSeconds::new(duration.as_secs())
            });
        let decision = self
            .config
            .admit(request.method.as_str(), request.uri.path(), now);
        context.decision = Some(decision);
        if let GatewayDecision::Denied(reason) = decision {
            let body = denial_body(&context.request_id, reason);
            session.respond_error_with_body(403, body).await?;
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
        upstream_request.insert_header("Host", self.config.origin_server_name())?;
        upstream_request.insert_header("X-Xshield-Request-Id", &context.request_id)?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        context: &mut Self::CTX,
    ) -> PingoraResult<()> {
        upstream_response.insert_header("X-Xshield-Request-Id", &context.request_id)?;
        Ok(())
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
        let decision = context
            .decision
            .unwrap_or(GatewayDecision::Denied(ReasonCode::RequestNotConfigured));
        let (admission_outcome, reason, origin_state) = match decision {
            GatewayDecision::Allowed(reason) if error.is_some() => ("ALLOW", reason, "unknown"),
            GatewayDecision::Allowed(reason) => ("ALLOW", reason, "response_received"),
            GatewayDecision::Denied(reason) => ("DENY", reason, "not_sent"),
        };
        let request = session.req_header();
        let event = DecisionLog {
            event_type: "request.completed",
            request_id: &context.request_id,
            method: request.method.as_str(),
            terminal_state: if error.is_some() {
                "proxy_error"
            } else {
                "completed"
            },
            admission_outcome,
            admission_reason_code: reason.as_str(),
            origin_state,
            status,
            durability: "memory_only",
        };
        let mut stderr = io::stderr().lock();
        if serde_json::to_writer(&mut stderr, &event).is_ok() {
            let _result = writeln!(stderr);
            let _result = stderr.flush();
        }
    }
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
    let mut server = Server::new(None)?;
    server.bootstrap();
    let mut proxy = http_proxy_service(
        &server.configuration,
        Gateway {
            config: Arc::clone(&config),
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
