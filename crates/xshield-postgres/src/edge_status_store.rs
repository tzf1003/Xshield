//! Gateway heartbeats (docs/07-console-architecture.md sections 7.7.5 and 7.8.1).
//!
//! Each gateway instance upserts one row every ten seconds. The console reads
//! the rows to show whether a gateway is online, which configuration version
//! it has loaded, and whether it has dropped decision log rows.

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};

/// Seconds without a heartbeat after which an instance counts as offline.
pub const ONLINE_WINDOW_SECONDS: i64 = 30;

/// The last heartbeat of one gateway instance.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeStatus {
    /// Instance name (`HOSTNAME` on the gateway).
    pub edge: String,
    /// When the instance started.
    pub started_at: DateTime<Utc>,
    /// When this heartbeat was written.
    pub seen_at: DateTime<Utc>,
    /// Build version of the gateway.
    pub build: String,
    /// Listening address.
    pub listen: String,
    /// Whether the listener terminates TLS.
    pub tls: bool,
    /// Per site: the loaded version, or the error code that kept it from loading.
    pub sites: serde_json::Value,
    /// Live client sessions held in memory.
    pub sessions: i32,
    /// Decision rows waiting for the writer.
    pub queue: i32,
    /// Decision rows written since start.
    pub written: i64,
    /// Decision rows dropped because the queue was full, since start.
    pub dropped: i64,
    /// Bypass rows dropped on purpose under queue pressure, since start.
    pub dropped_bypass: i64,
    /// Rows lost because an insert failed, since start.
    pub write_errors: i64,
    /// Recent loss intervals, last 24 hours: one object per interval with
    /// `from_ms`, `to_ms`, `dropped`, `dropped_bypass` and `write_errors`.
    pub gaps: serde_json::Value,
    /// Jev route, endpoint host name, model, default timeout and prompt id. Never a key.
    pub jev: serde_json::Value,
    /// The gateway's effective run parameters.
    pub params: serde_json::Value,
}

impl EdgeStatus {
    /// Whether the heartbeat is fresh enough to count the instance as online.
    #[must_use]
    pub fn is_online(&self, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(self.seen_at) <= Duration::seconds(ONLINE_WINDOW_SECONDS)
    }
}

fn row_to_status(row: &PgRow) -> Result<EdgeStatus, sqlx::Error> {
    Ok(EdgeStatus {
        edge: row.try_get("edge")?,
        started_at: row.try_get("started_at")?,
        seen_at: row.try_get("seen_at")?,
        build: row.try_get("build")?,
        listen: row.try_get("listen")?,
        tls: row.try_get("tls")?,
        sites: row.try_get("sites")?,
        sessions: row.try_get("sessions")?,
        queue: row.try_get("queue")?,
        written: row.try_get("written")?,
        dropped: row.try_get("dropped")?,
        dropped_bypass: row.try_get("dropped_bypass")?,
        write_errors: row.try_get("write_errors")?,
        gaps: row.try_get("gaps")?,
        jev: row.try_get("jev")?,
        params: row.try_get("params")?,
    })
}

/// Lists every known gateway instance, by name.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn list(pool: &PgPool) -> Result<Vec<EdgeStatus>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT edge, started_at, seen_at, build, listen, tls, sites, sessions, queue,
                written, dropped, dropped_bypass, write_errors, gaps, jev, params
         FROM edge_status ORDER BY edge",
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(row_to_status).collect()
}
