//! Bounded accounting of requests that no site snapshot routes.
//!
//! A request for an unknown `Host` or listener port belongs to no site, so it
//! cannot be audited under one, and writing a durable event per request would
//! hand an attacker a way to fill the journal. Each refusal is therefore
//! counted in memory, per listener port, and the counts are written as one
//! `edge.unrouted_denied` summary per port and interval. Memory is bounded by
//! the number of listener ports; nothing grows with request volume.

use crate::durable_audit::DurableAudit;
use std::{collections::BTreeMap, sync::Mutex, time::Duration};

/// Longest `Host` sample kept for a window (the DNS name limit).
const SAMPLE_HOST_MAX: usize = 253;
/// Upper bound on distinct listener ports tracked at once. Ports come from the
/// edge's own sockets, never from the client, so this is defensive.
const PORTS_MAX: usize = 256;
/// How often counted refusals are written to the journal.
pub(crate) const FLUSH_INTERVAL: Duration = Duration::from_mins(1);

/// Refusals counted for one listener port since the last flush.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnroutedSummary {
    pub(crate) listener_port: u16,
    pub(crate) denied_count: u64,
    pub(crate) first_seen_unix: u64,
    pub(crate) last_seen_unix: u64,
    /// The first `Host` seen in the interval, only if it is printable ASCII.
    /// Attacker-controlled data: stored and published as data, never trusted.
    pub(crate) sample_host: Option<String>,
}

#[derive(Default)]
pub(crate) struct UnroutedDenials {
    windows: Mutex<BTreeMap<u16, UnroutedSummary>>,
}

/// A `Host` sample is kept only when it is printable ASCII within the DNS
/// length limit; anything else is reported without a sample.
fn sample(host: Option<&str>) -> Option<String> {
    host.filter(|host| {
        !host.is_empty()
            && host.len() <= SAMPLE_HOST_MAX
            && host.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    })
    .map(str::to_ascii_lowercase)
}

impl UnroutedDenials {
    /// Counts one refusal. Constant time; allocates only for the first host
    /// sample of a port's interval.
    pub(crate) fn record(&self, listener_port: u16, host: Option<&str>, now_unix: u64) {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !windows.contains_key(&listener_port) && windows.len() >= PORTS_MAX {
            return;
        }
        let window = windows
            .entry(listener_port)
            .or_insert_with(|| UnroutedSummary {
                listener_port,
                denied_count: 0,
                first_seen_unix: now_unix,
                last_seen_unix: now_unix,
                sample_host: sample(host),
            });
        window.denied_count = window.denied_count.saturating_add(1);
        window.last_seen_unix = window.last_seen_unix.max(now_unix);
    }

    /// Takes every pending summary for writing.
    pub(crate) fn take(&self) -> Vec<UnroutedSummary> {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *windows).into_values().collect()
    }

    /// Puts back summaries that could not be written, merging with anything
    /// counted meanwhile so no refusal is lost while the journal is closed.
    pub(crate) fn restore(&self, summaries: Vec<UnroutedSummary>) {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for summary in summaries {
            match windows.get_mut(&summary.listener_port) {
                Some(current) => {
                    current.denied_count =
                        current.denied_count.saturating_add(summary.denied_count);
                    current.first_seen_unix = current.first_seen_unix.min(summary.first_seen_unix);
                    current.last_seen_unix = current.last_seen_unix.max(summary.last_seen_unix);
                    // The earlier sample describes the earlier start of the interval.
                    current.sample_host = summary.sample_host.or(current.sample_host.take());
                }
                None => {
                    windows.insert(summary.listener_port, summary);
                }
            }
        }
    }
}

/// Writes the counted refusals once; failures are put back for the next try.
pub(crate) async fn flush_once(audit: &DurableAudit, denials: &UnroutedDenials) {
    let mut failed = Vec::new();
    for summary in denials.take() {
        if audit.record_unrouted(&summary).await.is_err() {
            failed.push(summary);
        }
    }
    if !failed.is_empty() {
        denials.restore(failed);
    }
}

/// Flushes on an interval and once more at shutdown.
pub(crate) async fn flush_unrouted_denials(
    audit: DurableAudit,
    denials: std::sync::Arc<UnroutedDenials>,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let stop = tokio::select! {
            () = tokio::time::sleep(interval) => false,
            _ = shutdown.changed() => true,
        };
        flush_once(&audit, &denials).await;
        if stop {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_per_port_without_growing_with_volume() {
        let denials = UnroutedDenials::default();
        for second in 0..100_000_u64 {
            denials.record(6188, Some("attacker.example"), 1_000 + second % 60);
        }
        denials.record(6189, None, 1_030);
        let mut summaries = denials.take();
        summaries.sort_by_key(|summary| summary.listener_port);
        assert_eq!(summaries.len(), 2, "one entry per port, not per request");
        assert_eq!(summaries[0].denied_count, 100_000);
        assert_eq!(summaries[0].first_seen_unix, 1_000);
        assert_eq!(summaries[0].last_seen_unix, 1_059);
        assert_eq!(
            summaries[0].sample_host.as_deref(),
            Some("attacker.example")
        );
        assert_eq!(summaries[1].denied_count, 1);
        assert_eq!(summaries[1].sample_host, None);
        assert!(denials.take().is_empty(), "taking drains the window");
    }

    #[test]
    fn host_samples_are_bounded_printable_ascii_only() {
        for (host, expected) in [
            (Some("Example.COM"), Some("example.com")),
            (Some("a.b-c.d"), Some("a.b-c.d")),
            (None, None),
            (Some(""), None),
            (Some("evil host"), None),
            (Some("line\nbreak"), None),
            (Some("nul\0"), None),
            (Some("caf\u{e9}.example"), None),
            (Some(&"a".repeat(254)), None),
        ] {
            assert_eq!(sample(host).as_deref(), expected, "{host:?}");
        }
        assert!(sample(Some(&"a".repeat(253))).is_some());
    }

    #[test]
    fn restored_counts_merge_with_new_ones() {
        let denials = UnroutedDenials::default();
        denials.record(6188, Some("first.example"), 100);
        denials.record(6188, None, 110);
        let pending = denials.take();
        // Counted while the journal was closed:
        denials.record(6188, Some("later.example"), 200);
        denials.record(6190, None, 205);
        denials.restore(pending);
        let mut merged = denials.take();
        merged.sort_by_key(|summary| summary.listener_port);
        assert_eq!(merged[0].denied_count, 3);
        assert_eq!(merged[0].first_seen_unix, 100);
        assert_eq!(merged[0].last_seen_unix, 200);
        assert_eq!(merged[0].sample_host.as_deref(), Some("first.example"));
        assert_eq!(merged[1].listener_port, 6190);
    }

    #[test]
    fn the_number_of_tracked_ports_is_bounded() {
        let denials = UnroutedDenials::default();
        for port in 1..=u16::try_from(PORTS_MAX + 50).unwrap() {
            denials.record(port, None, 1);
        }
        assert_eq!(denials.take().len(), PORTS_MAX);
    }
}
