//! Unauthenticated operations endpoints of the control plane: liveness,
//! readiness and Prometheus metrics, on their own listener.
//!
//! Like the edge's (gateway `ops_api`), nothing here describes the
//! deployment: no tenant, site, subject, path or address appears in a
//! response, and every metric label comes from a closed set. Detail stays
//! behind the authenticated management API.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};

use crate::ControlPlane;

/// Upper bounds, in seconds, of the request duration histogram buckets.
const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
/// How long a failed access-audit append keeps the process unready. Without
/// traffic nothing would clear a sticky flag, so it expires instead.
const AUDIT_FAILURE_HOLD_SECONDS: u64 = 30;
/// Bound on the database probe so a scrape never hangs on the pool.
const DATABASE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

/// Why the control plane is not ready. Process-wide facts, not topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotReady {
    /// An access-audit append failed recently; audited routes refuse.
    AuditUnavailable,
    /// The database did not answer the probe.
    DatabaseUnavailable,
}

impl NotReady {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AuditUnavailable => "AUDIT_UNAVAILABLE",
            Self::DatabaseUnavailable => "DATABASE_UNAVAILABLE",
        }
    }
}

/// Process counters shared by the API router and the ops listener.
#[derive(Debug, Default)]
pub struct ControlMetrics {
    responses: [AtomicU64; 5],
    buckets: [AtomicU64; DURATION_BUCKETS.len()],
    duration_count: AtomicU64,
    duration_sum_micros: AtomicU64,
    audit_failures: AtomicU64,
    last_audit_failure_unix: AtomicU64,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl ControlMetrics {
    fn record(&self, status: StatusCode, elapsed: Duration) {
        let class = usize::from(status.as_u16() / 100).clamp(1, 5) - 1;
        self.responses[class].fetch_add(1, Ordering::Relaxed);
        let seconds = elapsed.as_secs_f64();
        for (bucket, bound) in self.buckets.iter().zip(DURATION_BUCKETS) {
            if seconds <= bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.duration_count.fetch_add(1, Ordering::Relaxed);
        self.duration_sum_micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Records the outcome of one access-audit append.
    pub(crate) fn audit_append(&self, succeeded: bool) {
        if !succeeded {
            self.audit_failures.fetch_add(1, Ordering::Relaxed);
            self.last_audit_failure_unix
                .store(now_unix(), Ordering::Relaxed);
        }
    }

    fn audit_recently_failed(&self, now: u64) -> bool {
        let last = self.last_audit_failure_unix.load(Ordering::Relaxed);
        last != 0 && now.saturating_sub(last) < AUDIT_FAILURE_HOLD_SECONDS
    }

    fn render(&self, ready: Result<(), NotReady>) -> String {
        let mut text = String::new();
        let _ = writeln!(
            text,
            "# HELP xshield_control_ready Whether the control plane is ready (1) or not (0).\n\
             # TYPE xshield_control_ready gauge\nxshield_control_ready {}",
            u8::from(ready.is_ok())
        );
        for reason in [NotReady::AuditUnavailable, NotReady::DatabaseUnavailable] {
            let _ = writeln!(
                text,
                "xshield_control_not_ready{{reason=\"{}\"}} {}",
                reason.as_str(),
                u8::from(ready == Err(reason))
            );
        }
        text.push_str(
            "# HELP xshield_control_responses_total Management API responses by status class.\n\
             # TYPE xshield_control_responses_total counter\n",
        );
        for (class, count) in CLASSES.iter().zip(&self.responses) {
            let _ = writeln!(
                text,
                "xshield_control_responses_total{{class=\"{class}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        text.push_str(
            "# HELP xshield_control_request_duration_seconds Management API request duration.\n\
             # TYPE xshield_control_request_duration_seconds histogram\n",
        );
        for (bound, bucket) in DURATION_BUCKETS.iter().zip(&self.buckets) {
            let _ = writeln!(
                text,
                "xshield_control_request_duration_seconds_bucket{{le=\"{bound}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let count = self.duration_count.load(Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let sum = self.duration_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(
            text,
            "xshield_control_request_duration_seconds_bucket{{le=\"+Inf\"}} {count}\n\
             xshield_control_request_duration_seconds_sum {sum}\n\
             xshield_control_request_duration_seconds_count {count}"
        );
        let _ = writeln!(
            text,
            "# HELP xshield_control_audit_append_failures_total Access-audit appends that failed.\n\
             # TYPE xshield_control_audit_append_failures_total counter\n\
             xshield_control_audit_append_failures_total {}",
            self.audit_failures.load(Ordering::Relaxed)
        );
        text
    }
}

/// Counts every management API response; installed by [`crate::router`].
pub(crate) async fn track(
    State(metrics): State<Arc<ControlMetrics>>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let response = next.run(request).await;
    metrics.record(response.status(), started.elapsed());
    response
}

/// Whether `address` may carry the unauthenticated ops listener: loopback,
/// private, link-local or unspecified only, never a public address.
#[must_use]
pub fn ops_address_allowed(address: SocketAddr) -> bool {
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

async fn readiness(control: &ControlPlane) -> Result<(), NotReady> {
    if control.metrics.audit_recently_failed(now_unix()) {
        return Err(NotReady::AuditUnavailable);
    }
    match tokio::time::timeout(DATABASE_PROBE_TIMEOUT, control.catalog.ping()).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(NotReady::DatabaseUnavailable),
    }
}

/// The ops endpoints over the same control plane the API router serves.
pub fn ops_router(control: Arc<ControlPlane>) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(control)
}

async fn livez() -> Response {
    no_store(
        StatusCode::OK,
        "application/json",
        r#"{"live":true}"#.to_owned(),
    )
}

async fn readyz(State(control): State<Arc<ControlPlane>>) -> Response {
    match readiness(&control).await {
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

async fn metrics(State(control): State<Arc<ControlPlane>>) -> Response {
    let ready = readiness(&control).await;
    no_store(
        StatusCode::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        control.metrics.render(ready),
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

    #[test]
    fn responses_are_counted_by_class_and_bucketed() {
        let metrics = ControlMetrics::default();
        metrics.record(StatusCode::OK, Duration::from_millis(3));
        metrics.record(StatusCode::CREATED, Duration::from_millis(30));
        metrics.record(StatusCode::FORBIDDEN, Duration::from_millis(300));
        metrics.record(StatusCode::SERVICE_UNAVAILABLE, Duration::from_secs(20));
        let text = metrics.render(Ok(()));
        for line in [
            "xshield_control_ready 1",
            "xshield_control_responses_total{class=\"2xx\"} 2",
            "xshield_control_responses_total{class=\"4xx\"} 1",
            "xshield_control_responses_total{class=\"5xx\"} 1",
            "xshield_control_request_duration_seconds_bucket{le=\"0.005\"} 1",
            "xshield_control_request_duration_seconds_bucket{le=\"0.05\"} 2",
            "xshield_control_request_duration_seconds_bucket{le=\"10\"} 3",
            "xshield_control_request_duration_seconds_bucket{le=\"+Inf\"} 4",
            "xshield_control_request_duration_seconds_count 4",
            "xshield_control_audit_append_failures_total 0",
            "xshield_control_not_ready{reason=\"DATABASE_UNAVAILABLE\"} 0",
        ] {
            assert!(
                text.lines().any(|candidate| candidate == line),
                "{line}\n{text}"
            );
        }
    }

    #[test]
    fn an_audit_failure_holds_readiness_for_a_while_then_expires() {
        let metrics = ControlMetrics::default();
        assert!(!metrics.audit_recently_failed(now_unix()));
        metrics.audit_append(true);
        assert!(!metrics.audit_recently_failed(now_unix()));
        metrics.audit_append(false);
        let now = now_unix();
        assert!(metrics.audit_recently_failed(now));
        assert!(!metrics.audit_recently_failed(now + AUDIT_FAILURE_HOLD_SECONDS));
        let text = metrics.render(Err(NotReady::AuditUnavailable));
        assert!(text.contains("xshield_control_ready 0"));
        assert!(text.contains("xshield_control_audit_append_failures_total 1"));
        assert!(text.contains("xshield_control_not_ready{reason=\"AUDIT_UNAVAILABLE\"} 1"));
    }

    #[test]
    fn the_listener_stays_off_public_addresses() {
        for allowed in [
            "127.0.0.1:9",
            "10.1.2.3:9",
            "0.0.0.0:9",
            "[::1]:9",
            "[fd00::1]:9",
        ] {
            assert!(ops_address_allowed(allowed.parse().unwrap()), "{allowed}");
        }
        for refused in ["8.8.8.8:9", "[2001:4860::1]:9"] {
            assert!(!ops_address_allowed(refused.parse().unwrap()), "{refused}");
        }
    }
}
