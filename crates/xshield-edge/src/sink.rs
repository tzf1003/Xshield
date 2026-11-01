//! Decision log delivery (docs/03 section 3.4).
//!
//! The proxy never waits for storage: rows go into a bounded channel and a
//! background task writes them. When the channel is full the row is dropped
//! and counted, because a slow log must not slow the traffic it describes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::mpsc;
use xshield_core::context::DecisionRecord;

/// Rows waiting for the writer.
pub const QUEUE_CAPACITY: usize = 10_000;

/// The producer half, cheap to clone.
#[derive(Clone)]
pub struct DecisionSink {
    tx: mpsc::Sender<DecisionRecord>,
    dropped: Arc<AtomicU64>,
}

impl DecisionSink {
    /// A sink and the receiver a writer drains.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<DecisionRecord>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Queues a row; counts it as dropped when the queue is full or closed.
    pub fn send(&self, record: DecisionRecord) {
        if self.tx.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Rows dropped since start.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Writes rows to `decision_log` until the channel closes.
///
/// A failed insert is reported on stderr and the row is lost; the next row
/// tries again.
pub async fn write_postgres(pool: PgPool, mut rx: mpsc::Receiver<DecisionRecord>) {
    while let Some(record) = rx.recv().await {
        if let Err(error) = insert(&pool, &record).await {
            eprintln!("xshield-edge: decision log insert failed: {error}");
        }
    }
}

/// Writes rows to stdout as JSON lines; used without a database.
pub async fn write_stdout(mut rx: mpsc::Receiver<DecisionRecord>) {
    while let Some(record) = rx.recv().await {
        if let Ok(line) = serde_json::to_string(&record) {
            println!("{line}");
        }
    }
}

async fn insert(pool: &PgPool, record: &DecisionRecord) -> Result<(), sqlx::Error> {
    let jev = record
        .jev
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
    sqlx::query(
        "INSERT INTO decision_log \
         (at_millis, site, request_id, session, method, path, status, decision_path, outcome, jev) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(i64::try_from(record.at_millis).unwrap_or(i64::MAX))
    .bind(&record.site)
    .bind(&record.request_id)
    .bind(&record.session)
    .bind(&record.method)
    .bind(&record.path)
    .bind(record.status.map(i32::from))
    .bind(variant_name(&record.decision_path)?)
    .bind(variant_name(&record.outcome)?)
    .bind(jev)
    .execute(pool)
    .await
    .map(|_| ())
}

/// The `snake_case` name serde gives a unit enum variant.
fn variant_name(value: &impl Serialize) -> Result<String, sqlx::Error> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => Ok(text),
        Ok(_) => Err(sqlx::Error::Encode("expected a string variant".into())),
        Err(error) => Err(sqlx::Error::Encode(Box::new(error))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::context::{DecisionPath, Outcome};

    fn row() -> DecisionRecord {
        DecisionRecord {
            at_millis: 1,
            site: "s".into(),
            request_id: "r".into(),
            session: "x".into(),
            method: "GET".into(),
            path: "/".into(),
            status: Some(200),
            decision_path: DecisionPath::FastAllow,
            outcome: Outcome::Allowed,
            jev: None,
        }
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts() {
        let (sink, mut rx) = DecisionSink::channel(1);
        sink.send(row());
        sink.send(row());
        assert_eq!(sink.dropped(), 1);
        assert_eq!(rx.recv().await.expect("first").request_id, "r");
    }
}
