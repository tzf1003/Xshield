//! Unauthenticated operations endpoints: liveness, readiness and metrics.
//!
//! Orchestrators and scrapers cannot sign requests, so nothing here may
//! describe the deployment: no tenant, site, host, port, revision or origin
//! appears in any response, and every metric label comes from a closed set
//! (an outcome or a stable reason code). Per-site detail stays on the
//! authenticated `/internal/v1/health` channel.

use crate::durable_audit::AuditReadiness;
use crate::evidence_writer::EvidenceWriter;
use crate::listener_supervisor::ListenerSupervisor;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use xshield_core::audit::ReasonCode;
use xshield_gateway::edge_transport::TransportStatus;

/// Upper bounds, in seconds, of the request duration histogram buckets.
const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Why the edge is not ready. Both are process-wide facts, not topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotReady {
    /// The durable audit barrier is closed, so admission refuses everything.
    AuditUnavailable,
    /// No data-plane listener is bound.
    NoListeners,
}

impl NotReady {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AuditUnavailable => "AUDIT_UNAVAILABLE",
            Self::NoListeners => "NO_LISTENERS",
        }
    }
}

pub(crate) const fn readiness(audit_ready: bool, listener_count: usize) -> Result<(), NotReady> {
    if !audit_ready {
        return Err(NotReady::AuditUnavailable);
    }
    if listener_count == 0 {
        return Err(NotReady::NoListeners);
    }
    Ok(())
}

// A poisoned map only lost a concurrent increment; keep counting.
fn count_reason(map: &Mutex<BTreeMap<&'static str, u64>>, reason: ReasonCode) {
    let mut counts = map
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *counts.entry(reason.as_str()).or_default() += 1;
}

fn snapshot(map: &Mutex<BTreeMap<&'static str, u64>>) -> BTreeMap<&'static str, u64> {
    map.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// How one request ended, as counted by [`EdgeMetrics`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ending {
    /// Admitted and answered with the origin's (or the edge's own) reply.
    Served,
    /// A refusal an observe rollout forwarded and the origin answered; the
    /// reason is the refusal the enforced policy would have applied.
    Observed(ReasonCode),
    /// Refused before the origin, or the reply was withheld after it.
    Refused(ReasonCode),
    /// The proxy failed after admission; the origin outcome is unknown.
    ProxyFailed,
    /// The request ended before the gateway's filters ran.
    Unadmitted,
}

/// Process-lifetime request counters. They reset on restart.
#[derive(Default)]
pub(crate) struct EdgeMetrics {
    served: AtomicU64,
    proxy_failed: AtomicU64,
    unadmitted: AtomicU64,
    refused: Mutex<BTreeMap<&'static str, u64>>,
    observed: Mutex<BTreeMap<&'static str, u64>>,
    duration_buckets: [AtomicU64; DURATION_BUCKETS.len()],
    duration_count: AtomicU64,
    duration_sum_micros: AtomicU64,
    retention_passes: AtomicU64,
    retention_failures: Mutex<BTreeMap<&'static str, u64>>,
    retention_deleted: AtomicU64,
    retention_last_success: AtomicU64,
}

impl EdgeMetrics {
    pub(crate) fn record(&self, ending: Ending, elapsed: Duration) {
        match ending {
            Ending::Served => {
                self.served.fetch_add(1, Ordering::Relaxed);
            }
            Ending::ProxyFailed => {
                self.proxy_failed.fetch_add(1, Ordering::Relaxed);
            }
            Ending::Unadmitted => {
                self.unadmitted.fetch_add(1, Ordering::Relaxed);
            }
            Ending::Refused(reason) => count_reason(&self.refused, reason),
            Ending::Observed(reason) => count_reason(&self.observed, reason),
        }
        let seconds = elapsed.as_secs_f64();
        for (bound, bucket) in DURATION_BUCKETS.iter().zip(&self.duration_buckets) {
            if seconds <= *bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.duration_count.fetch_add(1, Ordering::Relaxed);
        self.duration_sum_micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// One pass of the in-process evidence retention: the ciphertext objects
    /// it deleted, or why it failed (a stable reason code) and what it had
    /// deleted by then.
    pub(crate) fn record_retention_pass(&self, outcome: Result<usize, (&'static str, usize)>) {
        self.retention_passes.fetch_add(1, Ordering::Relaxed);
        let deleted = match outcome {
            Ok(deleted) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs());
                self.retention_last_success.store(now, Ordering::Relaxed);
                deleted
            }
            Err((reason, deleted)) => {
                let mut counts = self
                    .retention_failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *counts.entry(reason).or_default() += 1;
                deleted
            }
        };
        self.retention_deleted.fetch_add(
            u64::try_from(deleted).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// The Prometheus text exposition (format 0.0.4) of every edge metric.
    /// `evidence` is the capture budget's remaining bytes and files, when
    /// the edge captures evidence.
    pub(crate) fn render(
        &self,
        ready: Result<(), NotReady>,
        transport: TransportStatus,
        evidence: Option<(u64, u64)>,
    ) -> String {
        let mut out = String::with_capacity(4096);
        gauge(
            &mut out,
            "xshield_edge_ready",
            "1 when the edge admits traffic: audit barrier open and a listener bound.",
            u64::from(ready.is_ok()),
        );
        gauge(
            &mut out,
            "xshield_edge_audit_ready",
            "1 when the durable audit barrier is open.",
            u64::from(ready != Err(NotReady::AuditUnavailable)),
        );
        let _ = writeln!(
            out,
            "# HELP xshield_edge_requests_total Requests by how they ended.\n\
             # TYPE xshield_edge_requests_total counter"
        );
        let _ = writeln!(
            out,
            "xshield_edge_requests_total{{outcome=\"served\"}} {}",
            self.served.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "xshield_edge_requests_total{{outcome=\"proxy_failed\"}} {}",
            self.proxy_failed.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "xshield_edge_requests_total{{outcome=\"unadmitted\"}} {}",
            self.unadmitted.load(Ordering::Relaxed)
        );
        let refused = snapshot(&self.refused);
        let observed = snapshot(&self.observed);
        let refused_total: u64 = refused.values().sum();
        let observed_total: u64 = observed.values().sum();
        let _ = writeln!(
            out,
            "xshield_edge_requests_total{{outcome=\"refused\"}} {refused_total}"
        );
        let _ = writeln!(
            out,
            "xshield_edge_requests_total{{outcome=\"observed\"}} {observed_total}"
        );
        by_reason(
            &mut out,
            "xshield_edge_refusals_total",
            "Refused requests and withheld replies by stable reason code.",
            &refused,
        );
        by_reason(
            &mut out,
            "xshield_edge_observed_refusals_total",
            "Requests an observe rollout forwarded, by the refusal enforcement would have applied.",
            &observed,
        );
        let _ = writeln!(
            out,
            "# HELP xshield_edge_request_duration_seconds Time from admission start to the final log.\n\
             # TYPE xshield_edge_request_duration_seconds histogram"
        );
        for (bound, bucket) in DURATION_BUCKETS.iter().zip(&self.duration_buckets) {
            let _ = writeln!(
                out,
                "xshield_edge_request_duration_seconds_bucket{{le=\"{bound}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let count = self.duration_count.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "xshield_edge_request_duration_seconds_bucket{{le=\"+Inf\"}} {count}"
        );
        #[allow(clippy::cast_precision_loss)]
        let sum = self.duration_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(out, "xshield_edge_request_duration_seconds_sum {sum}");
        let _ = writeln!(out, "xshield_edge_request_duration_seconds_count {count}");
        render_transport(&mut out, transport);
        self.render_evidence(&mut out, evidence);
        out
    }

    fn render_evidence(&self, out: &mut String, evidence: Option<(u64, u64)>) {
        if let Some((bytes, files)) = evidence {
            gauge(
                out,
                "xshield_edge_evidence_capacity_remaining_bytes",
                "Bytes the evidence writer may still charge before captures are refused.",
                bytes,
            );
            gauge(
                out,
                "xshield_edge_evidence_capacity_remaining_files",
                "Files the evidence writer may still create before captures are refused.",
                files,
            );
        }
        counter(
            out,
            "xshield_edge_evidence_retention_passes_total",
            "Passes of the in-process evidence retention, successful or not.",
            self.retention_passes.load(Ordering::Relaxed),
        );
        by_reason(
            out,
            "xshield_edge_evidence_retention_failures_total",
            "Failed evidence retention passes by stable reason code.",
            &snapshot(&self.retention_failures),
        );
        counter(
            out,
            "xshield_edge_evidence_retention_deleted_total",
            "Evidence ciphertext objects the in-process retention deleted.",
            self.retention_deleted.load(Ordering::Relaxed),
        );
        gauge(
            out,
            "xshield_edge_evidence_retention_last_success_timestamp_seconds",
            "Unix time of the last fully successful retention pass; 0 before the first.",
            self.retention_last_success.load(Ordering::Relaxed),
        );
    }
}

/// Connection-setup and certificate state shared with the health endpoint.
fn render_transport(out: &mut String, transport: TransportStatus) {
    counter(
        out,
        "xshield_edge_tls_handshake_failures_total",
        "TLS handshakes that failed or exceeded their deadline.",
        transport.tls_handshake_failures,
    );
    gauge(
        out,
        "xshield_edge_tls_certificates",
        "Configured TLS certificate/key pairs, the primary included.",
        transport.tls_certificates,
    );
    counter(
        out,
        "xshield_edge_tls_reloads_total",
        "Certificate reloads that replaced the certificates after their files changed.",
        transport.tls_reloads,
    );
    counter(
        out,
        "xshield_edge_tls_reload_failures_total",
        "Changed certificate files refused; the previous certificates stayed in service.",
        transport.tls_reload_failures,
    );
    counter(
        out,
        "xshield_edge_proxy_header_rejections_total",
        "Trusted balancer connections refused for their PROXY header.",
        transport.proxy_header_rejections,
    );
    counter(
        out,
        "xshield_edge_connection_setup_shed_total",
        "Connections closed because every setup slot was busy.",
        transport.setup_shed,
    );
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    );
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
    );
}

fn by_reason(out: &mut String, name: &str, help: &str, counts: &BTreeMap<&'static str, u64>) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
    for (reason, count) in counts {
        let _ = writeln!(out, "{name}{{reason_code=\"{reason}\"}} {count}");
    }
}

/// Accepts loopback, private, link-local and unspecified addresses. A public
/// address is refused: the endpoints are unauthenticated and belong on a
/// management network even though they disclose no topology.
pub(crate) fn ops_address_allowed(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

#[derive(Clone)]
pub(crate) struct OpsState {
    supervisor: Arc<ListenerSupervisor>,
    audit: AuditReadiness,
    metrics: Arc<EdgeMetrics>,
    evidence: Option<Arc<EvidenceWriter>>,
}

impl OpsState {
    pub(crate) fn new(
        supervisor: Arc<ListenerSupervisor>,
        audit: AuditReadiness,
        metrics: Arc<EdgeMetrics>,
        evidence: Option<Arc<EvidenceWriter>>,
    ) -> Self {
        Self {
            supervisor,
            audit,
            metrics,
            evidence,
        }
    }

    async fn readiness(&self) -> Result<(), NotReady> {
        readiness(
            self.audit.is_ready(),
            self.supervisor.listener_count().await,
        )
    }
}

pub(crate) async fn serve(listener: TcpListener, state: OpsState) -> Result<(), std::io::Error> {
    axum::serve(listener, router(state)).await
}

fn router(state: OpsState) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn livez() -> Response {
    no_store(
        StatusCode::OK,
        "application/json",
        r#"{"live":true}"#.to_owned(),
    )
}

async fn readyz(State(state): State<OpsState>) -> Response {
    match state.readiness().await {
        Ok(()) => no_store(
            StatusCode::OK,
            "application/json",
            r#"{"ready":true}"#.to_owned(),
        ),
        Err(reason) => no_store(
            StatusCode::SERVICE_UNAVAILABLE,
            "application/json",
            format!(r#"{{"ready":false,"reason_code":"{}"}}"#, reason.as_str()),
        ),
    }
}

async fn metrics(State(state): State<OpsState>) -> Response {
    let ready = state.readiness().await;
    let body = state.metrics.render(
        ready,
        state.supervisor.transport_status(),
        state
            .evidence
            .as_deref()
            .and_then(EvidenceWriter::remaining),
    );
    no_store(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        body,
    )
}

fn no_store(status: StatusCode, content_type: &'static str, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> TransportStatus {
        TransportStatus {
            tls_enabled: true,
            tls_certificates: 2,
            tls_reloads: 4,
            tls_reload_failures: 5,
            tls_handshake_failures: 3,
            proxy_protocol_enabled: false,
            proxy_header_rejections: 0,
            setup_shed: 1,
        }
    }

    #[test]
    fn readiness_names_the_first_closed_gate() {
        assert_eq!(readiness(true, 2), Ok(()));
        assert_eq!(readiness(false, 2), Err(NotReady::AuditUnavailable));
        assert_eq!(readiness(false, 0), Err(NotReady::AuditUnavailable));
        assert_eq!(readiness(true, 0), Err(NotReady::NoListeners));
    }

    #[test]
    fn metrics_count_each_ending_and_bucket_durations() {
        let metrics = EdgeMetrics::default();
        metrics.record(Ending::Served, Duration::from_millis(3));
        metrics.record(Ending::Served, Duration::from_millis(30));
        metrics.record(
            Ending::Refused(ReasonCode::AuthRequired),
            Duration::from_millis(1),
        );
        metrics.record(Ending::ProxyFailed, Duration::from_secs(20));
        metrics.record(Ending::Unadmitted, Duration::from_secs(60));
        metrics.record(
            Ending::Observed(ReasonCode::UiActionNotAvailable),
            Duration::from_millis(2),
        );
        let text = metrics.render(Ok(()), transport(), None);
        assert!(text.contains("xshield_edge_ready 1\n"));
        assert!(text.contains("xshield_edge_requests_total{outcome=\"served\"} 2\n"));
        assert!(text.contains("xshield_edge_requests_total{outcome=\"refused\"} 1\n"));
        assert!(text.contains("xshield_edge_requests_total{outcome=\"proxy_failed\"} 1\n"));
        assert!(text.contains(&format!(
            "xshield_edge_refusals_total{{reason_code=\"{}\"}} 1\n",
            ReasonCode::AuthRequired.as_str()
        )));
        assert!(text.contains("xshield_edge_request_duration_seconds_bucket{le=\"0.005\"} 3\n"));
        assert!(text.contains("xshield_edge_request_duration_seconds_bucket{le=\"0.05\"} 4\n"));
        assert!(text.contains("xshield_edge_request_duration_seconds_bucket{le=\"10\"} 4\n"));
        assert!(text.contains("xshield_edge_requests_total{outcome=\"unadmitted\"} 1\n"));
        assert!(text.contains("xshield_edge_requests_total{outcome=\"observed\"} 1\n"));
        assert!(text.contains(
            "xshield_edge_observed_refusals_total{reason_code=\"UI_ACTION_NOT_AVAILABLE\"} 1\n"
        ));
        assert!(text.contains("xshield_edge_request_duration_seconds_bucket{le=\"+Inf\"} 6\n"));
        assert!(text.contains("xshield_edge_request_duration_seconds_count 6\n"));
        assert!(text.contains("xshield_edge_tls_handshake_failures_total 3\n"));
        assert!(text.contains("xshield_edge_connection_setup_shed_total 1\n"));
        assert!(text.contains("xshield_edge_tls_certificates 2\n"));
        assert!(text.contains("xshield_edge_tls_reloads_total 4\n"));
        assert!(text.contains("xshield_edge_tls_reload_failures_total 5\n"));
    }

    #[test]
    fn metrics_report_a_closed_audit_barrier() {
        let text =
            EdgeMetrics::default().render(Err(NotReady::AuditUnavailable), transport(), None);
        assert!(text.contains("xshield_edge_ready 0\n"));
        assert!(text.contains("xshield_edge_audit_ready 0\n"));
        let text = EdgeMetrics::default().render(Err(NotReady::NoListeners), transport(), None);
        assert!(text.contains("xshield_edge_ready 0\n"));
        assert!(text.contains("xshield_edge_audit_ready 1\n"));
    }

    #[test]
    fn every_line_is_a_comment_or_a_closed_set_sample() {
        let metrics = EdgeMetrics::default();
        metrics.record(
            Ending::Refused(ReasonCode::SiteConfigUnavailable),
            Duration::ZERO,
        );
        metrics.record_retention_pass(Err(("EVIDENCE_PURGE_UNAVAILABLE", 0)));
        for line in metrics.render(Ok(()), transport(), Some((1, 1))).lines() {
            assert!(
                line.starts_with("# ") || line.starts_with("xshield_edge_"),
                "{line}"
            );
        }
    }

    #[test]
    fn metrics_count_retention_passes_and_report_capacity() {
        let metrics = EdgeMetrics::default();
        let text = metrics.render(Ok(()), transport(), None);
        assert!(!text.contains("xshield_edge_evidence_capacity"));
        assert!(
            text.contains("xshield_edge_evidence_retention_last_success_timestamp_seconds 0\n")
        );
        metrics.record_retention_pass(Ok(3));
        metrics.record_retention_pass(Err(("EVIDENCE_PURGE_FAILED", 2)));
        metrics.record_retention_pass(Err(("EVIDENCE_PURGE_FAILED", 0)));
        let text = metrics.render(Ok(()), transport(), Some((4096, 7)));
        assert!(text.contains("xshield_edge_evidence_capacity_remaining_bytes 4096\n"));
        assert!(text.contains("xshield_edge_evidence_capacity_remaining_files 7\n"));
        assert!(text.contains("xshield_edge_evidence_retention_passes_total 3\n"));
        assert!(text.contains("xshield_edge_evidence_retention_deleted_total 5\n"));
        assert!(text.contains(
            "xshield_edge_evidence_retention_failures_total{reason_code=\"EVIDENCE_PURGE_FAILED\"} 2\n"
        ));
        assert!(
            !text.contains("xshield_edge_evidence_retention_last_success_timestamp_seconds 0\n")
        );
    }

    #[test]
    fn only_management_addresses_may_serve_ops() {
        for allowed in [
            "127.0.0.1:9554",
            "10.0.0.5:9554",
            "172.16.1.1:9554",
            "192.168.1.1:9554",
            "169.254.1.1:9554",
            "0.0.0.0:9554",
            "[::1]:9554",
            "[::]:9554",
            "[fd00::1]:9554",
            "[fe80::1]:9554",
        ] {
            assert!(
                ops_address_allowed(allowed.parse().expect("address")),
                "{allowed}"
            );
        }
        for refused in ["8.8.8.8:9554", "[2001:db8::1]:9554", "203.0.113.9:9554"] {
            assert!(
                !ops_address_allowed(refused.parse().expect("address")),
                "{refused}"
            );
        }
    }
}
