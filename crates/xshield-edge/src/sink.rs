//! Decision log delivery (docs/07 sections 7.4.1 and 7.7.4).
//!
//! The proxy never waits for storage: a row goes into a bounded channel and a
//! background writer stores rows in batches. Under pressure bypass rows are
//! dropped first, because the judged requests are the trace the console needs.
//! Every loss is counted, and counted again per minute so the heartbeat can say
//! when it happened.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sqlx::{PgPool, QueryBuilder};
use tokio::sync::mpsc::{self, Receiver, WeakSender};
use xshield_core::context::{DecisionPath, DecisionRecord, JevRecord};

/// Rows waiting for the writer.
pub const QUEUE_CAPACITY: usize = 10_000;
/// Rows in one multi-row `INSERT`.
pub const BATCH_MAX: usize = 500;
/// How long a batch waits for more rows once it holds one.
pub const BATCH_WAIT: Duration = Duration::from_millis(250);
/// The pause before the one retry of a failed batch.
pub const RETRY_DELAY: Duration = Duration::from_millis(500);
/// Losses are remembered for this many minutes.
pub const LOSS_MINUTES: u64 = 24 * 60;
/// At most this many gaps are reported: the newest ones.
pub const GAPS_MAX: usize = 50;

const MINUTE_MS: u64 = 60_000;

const INSERT_HEAD: &str = "INSERT INTO decision_log \
    (at_millis, request_id, site, site_version, edge, host, client, session, context, \
     method, path, query, status, decision_path, outcome, total_ms, jev_ms, jev_access, \
     jev_attack, jev_confidence, jev_failure, trace, jev) ";

/// The current Unix time in milliseconds.
#[must_use]
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Rows lost in some period, by cause.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Loss {
    dropped: u64,
    dropped_bypass: u64,
    write_errors: u64,
}

impl Loss {
    fn absorb(&mut self, other: Loss) {
        self.dropped = self.dropped.saturating_add(other.dropped);
        self.dropped_bypass = self.dropped_bypass.saturating_add(other.dropped_bypass);
        self.write_errors = self.write_errors.saturating_add(other.write_errors);
    }
}

/// A period with lost rows, as the heartbeat reports it (docs/07 section 7.7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Gap {
    /// Start of the first lost minute, Unix milliseconds.
    pub from_ms: u64,
    /// End of the last lost minute, Unix milliseconds.
    pub to_ms: u64,
    /// Rows dropped because the queue was full.
    pub dropped: u64,
    /// Bypass rows dropped under queue pressure.
    pub dropped_bypass: u64,
    /// Rows the writer could not store.
    pub write_errors: u64,
}

impl Gap {
    fn of(minute: u64, loss: Loss) -> Self {
        let mut gap = Self {
            from_ms: minute * MINUTE_MS,
            to_ms: (minute + 1) * MINUTE_MS,
            dropped: 0,
            dropped_bypass: 0,
            write_errors: 0,
        };
        gap.add(loss);
        gap
    }

    fn add(&mut self, loss: Loss) {
        self.dropped = self.dropped.saturating_add(loss.dropped);
        self.dropped_bypass = self.dropped_bypass.saturating_add(loss.dropped_bypass);
        self.write_errors = self.write_errors.saturating_add(loss.write_errors);
    }
}

/// Counters shared by the producer, the writer, and the heartbeat.
#[derive(Default)]
struct Shared {
    written: AtomicU64,
    dropped: AtomicU64,
    dropped_bypass: AtomicU64,
    write_errors: AtomicU64,
    minutes: Mutex<BTreeMap<u64, Loss>>,
}

impl Shared {
    /// Counts `lost` rows whose requests happened in the minute of `at_millis`.
    fn lose(&self, at_millis: u64, lost: Loss) {
        add(&self.dropped, lost.dropped);
        add(&self.dropped_bypass, lost.dropped_bypass);
        add(&self.write_errors, lost.write_errors);
        let minute = at_millis / MINUTE_MS;
        let mut minutes = self.minutes.lock().unwrap_or_else(PoisonError::into_inner);
        minutes.entry(minute).or_default().absorb(lost);
        forget_before(&mut minutes, now_millis() / MINUTE_MS, LOSS_MINUTES);
    }

    /// The losses as runs of consecutive minutes, the newest [`GAPS_MAX`] of
    /// them, oldest first. `now_minute` is the current Unix minute.
    fn gaps_at(&self, now_minute: u64) -> Vec<Gap> {
        let mut minutes = self.minutes.lock().unwrap_or_else(PoisonError::into_inner);
        forget_before(&mut minutes, now_minute, LOSS_MINUTES);
        let mut gaps: Vec<Gap> = Vec::new();
        let mut previous: Option<u64> = None;
        for (&minute, loss) in minutes.iter() {
            let continues = previous.is_some_and(|last| last + 1 == minute);
            match gaps.last_mut() {
                Some(gap) if continues => {
                    gap.to_ms = (minute + 1) * MINUTE_MS;
                    gap.add(*loss);
                }
                _ => gaps.push(Gap::of(minute, *loss)),
            }
            previous = Some(minute);
        }
        let skipped = gaps.len().saturating_sub(GAPS_MAX);
        gaps.split_off(skipped)
    }
}

fn add(counter: &AtomicU64, by: u64) {
    counter.fetch_add(by, Ordering::Relaxed);
}

/// Forgets the minutes older than the window that ends at `now_minute`.
fn forget_before(minutes: &mut BTreeMap<u64, Loss>, now_minute: u64, window: u64) {
    let cutoff = now_minute.saturating_sub(window);
    while let Some((&minute, _)) = minutes.first_key_value()
        && minute < cutoff
    {
        minutes.pop_first();
    }
}

/// The producer half, cheap to clone.
#[derive(Clone)]
pub struct DecisionSink {
    tx: mpsc::Sender<DecisionRecord>,
    shared: Arc<Shared>,
}

impl DecisionSink {
    /// A sink and the receiver a writer drains.
    #[must_use]
    pub fn channel(capacity: usize) -> (Self, Receiver<DecisionRecord>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                shared: Arc::new(Shared::default()),
            },
            rx,
        )
    }

    /// The counters for the writer and the heartbeat. They hold no sender, so
    /// they never keep the queue open.
    #[must_use]
    pub fn counters(&self) -> Counters {
        Counters {
            shared: Arc::clone(&self.shared),
            queue: self.tx.downgrade(),
        }
    }

    /// Queues a row without waiting.
    ///
    /// At 80% of capacity or more a bypass row is dropped and counted as
    /// `dropped_bypass`; judged rows still queue. A row that finds the queue
    /// full (or its writer gone) is dropped and counted as `dropped`.
    pub fn send(&self, record: DecisionRecord) {
        let at_millis = record.at_millis;
        if record.decision_path == DecisionPath::Bypass && self.pressured() {
            self.shared.lose(
                at_millis,
                Loss {
                    dropped_bypass: 1,
                    ..Loss::default()
                },
            );
        } else if self.tx.try_send(record).is_err() {
            self.shared.lose(
                at_millis,
                Loss {
                    dropped: 1,
                    ..Loss::default()
                },
            );
        }
    }

    /// Whether the queue holds at least 80% of its capacity.
    fn pressured(&self) -> bool {
        let capacity = self.tx.max_capacity();
        let used = capacity.saturating_sub(self.tx.capacity());
        used.saturating_mul(5) >= capacity.saturating_mul(4)
    }
}

/// Read access to the delivery counters, and the writer's way to record what
/// it stored or lost.
#[derive(Clone)]
pub struct Counters {
    shared: Arc<Shared>,
    queue: WeakSender<DecisionRecord>,
}

impl Counters {
    /// Rows stored since start.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.shared.written.load(Ordering::Relaxed)
    }

    /// Rows dropped because the queue was full, since start.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    /// Bypass rows dropped under queue pressure, since start.
    #[must_use]
    pub fn dropped_bypass(&self) -> u64 {
        self.shared.dropped_bypass.load(Ordering::Relaxed)
    }

    /// Rows the writer could not store, since start.
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.shared.write_errors.load(Ordering::Relaxed)
    }

    /// Rows waiting for the writer.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue
            .upgrade()
            .map_or(0, |tx| tx.max_capacity().saturating_sub(tx.capacity()))
    }

    /// The losses of the last 24 hours (see [`Gap`]).
    #[must_use]
    pub fn gaps(&self) -> Vec<Gap> {
        self.shared.gaps_at(now_millis() / MINUTE_MS)
    }

    fn wrote(&self, rows: usize) {
        add(
            &self.shared.written,
            u64::try_from(rows).unwrap_or(u64::MAX),
        );
    }

    fn lost_to_writer(&self, batch: &[DecisionRecord]) {
        for record in batch {
            self.shared.lose(
                record.at_millis,
                Loss {
                    write_errors: 1,
                    ..Loss::default()
                },
            );
        }
    }
}

/// Writes rows to `decision_log` until the channel closes.
///
/// Rows go in batches of at most [`BATCH_MAX`], collected for at most
/// [`BATCH_WAIT`]. A failed batch is retried once after [`RETRY_DELAY`]; when
/// the retry fails too the batch is dropped and its rows count as write errors.
pub async fn write_postgres(pool: PgPool, mut rx: Receiver<DecisionRecord>, counters: Counters) {
    while let Some(batch) = next_batch(&mut rx).await {
        store(&pool, &batch, &counters).await;
    }
}

/// Writes each row to standard output as one JSON line: the same object the
/// database row is built from, for development without a database (docs/07
/// section 7.7.4). A line that cannot be written counts as a write error.
pub async fn write_stdout(mut rx: Receiver<DecisionRecord>, counters: Counters) {
    while let Some(record) = rx.recv().await {
        if write_line(&record).is_ok() {
            counters.wrote(1);
        } else {
            counters.lost_to_writer(std::slice::from_ref(&record));
        }
    }
}

/// Writes one record as a JSON line. It uses blocking standard output, because
/// tokio's stdout needs a feature this crate does not enable; the mode is for
/// development, and each line is small.
fn write_line(record: &DecisionRecord) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut out = std::io::stdout();
    out.write_all(&line)?;
    out.flush()
}

/// The next batch: one row, then whatever arrives within [`BATCH_WAIT`] up to
/// [`BATCH_MAX`]. `None` once the channel is closed and drained.
async fn next_batch(rx: &mut Receiver<DecisionRecord>) -> Option<Vec<DecisionRecord>> {
    let first = rx.recv().await?;
    let mut batch = Vec::with_capacity(BATCH_MAX);
    batch.push(first);
    let deadline = tokio::time::Instant::now() + BATCH_WAIT;
    while batch.len() < BATCH_MAX {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(record)) => batch.push(record),
            Ok(None) | Err(_) => break,
        }
    }
    Some(batch)
}

async fn store(pool: &PgPool, batch: &[DecisionRecord], counters: &Counters) {
    let outcome = match batch.iter().map(Row::of).collect::<Result<Vec<_>, _>>() {
        Ok(rows) => attempt_twice(pool, &rows).await,
        Err(error) => Err(error),
    };
    match outcome {
        Ok(()) => counters.wrote(batch.len()),
        Err(error) => {
            eprintln!(
                "xshield-edge: {} decision log row(s) lost: {error}",
                batch.len()
            );
            counters.lost_to_writer(batch);
        }
    }
}

async fn attempt_twice(pool: &PgPool, rows: &[Row<'_>]) -> Result<(), sqlx::Error> {
    match insert(pool, rows).await {
        Ok(()) => Ok(()),
        Err(error) => {
            eprintln!("xshield-edge: decision log batch failed, retrying once: {error}");
            tokio::time::sleep(RETRY_DELAY).await;
            insert(pool, rows).await
        }
    }
}

async fn insert(pool: &PgPool, rows: &[Row<'_>]) -> Result<(), sqlx::Error> {
    let mut builder = QueryBuilder::new(INSERT_HEAD);
    builder.push_values(rows, |mut row_values, row| {
        row_values
            .push_bind(row.at_millis)
            .push_bind(row.request_id)
            .push_bind(row.site)
            .push_bind(row.site_version)
            .push_bind(row.edge)
            .push_bind(row.host)
            .push_bind(row.client)
            .push_bind(row.session)
            .push_bind(row.context.as_deref())
            .push_bind(row.method)
            .push_bind(row.path)
            .push_bind(row.query)
            .push_bind(row.status)
            .push_bind(row.decision_path.as_str())
            .push_bind(row.outcome.as_str())
            .push_bind(row.total_ms)
            .push_bind(row.jev_ms)
            .push_bind(row.jev_access.as_deref())
            .push_bind(row.jev_attack.as_deref())
            .push_bind(row.jev_confidence)
            .push_bind(row.jev_failure)
            .push_bind(&row.trace)
            .push_bind(row.jev.as_ref());
    });
    builder.build().execute(pool).await.map(|_| ())
}

/// One `decision_log` row, with the derived columns of docs/07 section 7.8.1.
struct Row<'a> {
    at_millis: i64,
    request_id: &'a str,
    site: Option<&'a str>,
    site_version: Option<i64>,
    edge: &'a str,
    host: &'a str,
    client: &'a str,
    session: &'a str,
    context: Option<String>,
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    status: Option<i16>,
    decision_path: String,
    outcome: String,
    total_ms: Option<i32>,
    jev_ms: Option<i32>,
    jev_access: Option<String>,
    jev_attack: Option<String>,
    jev_confidence: Option<f64>,
    jev_failure: Option<&'a str>,
    trace: serde_json::Value,
    jev: Option<serde_json::Value>,
}

impl<'a> Row<'a> {
    fn of(record: &'a DecisionRecord) -> Result<Self, sqlx::Error> {
        let jev = record.jev.as_ref();
        Ok(Self {
            at_millis: i64::try_from(record.at_millis).map_err(encode)?,
            request_id: &record.request_id,
            site: record.site.as_deref(),
            site_version: record.site_version,
            edge: &record.edge,
            host: &record.host,
            client: &record.client,
            session: &record.session,
            context: record.context.map(|kind| variant_name(&kind)).transpose()?,
            method: &record.method,
            path: &record.path,
            query: record.query.as_deref(),
            status: record.status.and_then(|status| i16::try_from(status).ok()),
            decision_path: variant_name(&record.decision_path)?,
            outcome: variant_name(&record.outcome)?,
            total_ms: record
                .trace
                .timing
                .total_ms
                .and_then(|ms| i32::try_from(ms).ok()),
            jev_ms: jev.and_then(|jev| i32::try_from(jev.millis).ok()),
            jev_access: jev.and_then(|jev| top_option(&jev.access)),
            jev_attack: jev.and_then(|jev| top_option(&jev.attack)),
            jev_confidence: jev.and_then(confidence),
            jev_failure: jev.and_then(|jev| jev.failure.as_deref()),
            trace: serde_json::to_value(&record.trace).map_err(encode)?,
            jev: jev.map(serde_json::to_value).transpose().map_err(encode)?,
        })
    }
}

fn encode(error: impl std::error::Error + Send + Sync + 'static) -> sqlx::Error {
    sqlx::Error::Encode(Box::new(error))
}

/// The option with the highest probability; the first one wins a tie.
fn top_option(probabilities: &BTreeMap<String, f64>) -> Option<String> {
    probabilities
        .iter()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .map(|(option, _)| option.clone())
}

/// The smaller of the two questions' highest probabilities (docs/07 section 7.5.1).
fn confidence(jev: &JevRecord) -> Option<f64> {
    let highest = |map: &BTreeMap<String, f64>| map.values().copied().max_by(f64::total_cmp);
    Some(highest(&jev.access)?.min(highest(&jev.attack)?))
}

/// The `snake_case` name serde gives a unit enum variant.
fn variant_name(value: &impl Serialize) -> Result<String, sqlx::Error> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => Ok(text),
        Ok(_) => Err(sqlx::Error::Encode("expected a string variant".into())),
        Err(error) => Err(encode(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::context::{Outcome, Trace};

    fn record(path: DecisionPath, at_millis: u64) -> DecisionRecord {
        DecisionRecord {
            at_millis,
            request_id: "req_00000000000000000000000000000001".to_owned(),
            site: Some("emr".to_owned()),
            site_version: Some(1),
            edge: "edge-test".to_owned(),
            host: "emr.test".to_owned(),
            client: "192.0.2.1".to_owned(),
            session: String::new(),
            context: None,
            method: "GET".to_owned(),
            path: "/".to_owned(),
            query: None,
            status: Some(200),
            decision_path: path,
            outcome: Outcome::Allowed,
            trace: Trace::default(),
            jev: None,
        }
    }

    fn now() -> u64 {
        now_millis()
    }

    #[test]
    fn a_full_queue_drops_and_counts() {
        let (sink, _rx) = DecisionSink::channel(1);
        let counters = sink.counters();
        sink.send(record(DecisionPath::FastAllow, now()));
        sink.send(record(DecisionPath::FastAllow, now()));
        assert_eq!(counters.dropped(), 1);
        assert_eq!(counters.dropped_bypass(), 0);
        assert_eq!(counters.queued(), 1);
        let gaps = counters.gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].dropped, 1);
    }

    #[test]
    fn under_pressure_bypass_rows_go_first_and_judged_rows_still_queue() {
        let (sink, _rx) = DecisionSink::channel(10);
        let counters = sink.counters();
        for _ in 0..8 {
            sink.send(record(DecisionPath::JevAllow, now()));
        }
        assert_eq!(counters.queued(), 8);
        // At 80% a bypass row is refused, and nothing else changes.
        sink.send(record(DecisionPath::Bypass, now()));
        assert_eq!(counters.dropped_bypass(), 1);
        assert_eq!(counters.queued(), 8);
        // Judged rows still queue up to the capacity.
        sink.send(record(DecisionPath::JevDeny, now()));
        sink.send(record(DecisionPath::JevDeny, now()));
        assert_eq!(counters.queued(), 10);
        assert_eq!(counters.dropped(), 0);
        // A full queue drops whatever arrives.
        sink.send(record(DecisionPath::JevDeny, now()));
        assert_eq!(counters.dropped(), 1);
        assert_eq!(counters.dropped_bypass(), 1);
    }

    #[test]
    fn consecutive_lost_minutes_merge_into_one_gap() {
        let shared = Shared::default();
        let base = now() / MINUTE_MS - 100;
        let lost = |minute: u64| {
            shared.lose(
                minute * MINUTE_MS + 1,
                Loss {
                    dropped: 2,
                    ..Loss::default()
                },
            );
        };
        for minute in [base, base + 1, base + 2, base + 5] {
            lost(minute);
        }
        let gaps = shared.gaps_at(base + 100);
        assert_eq!(
            gaps,
            vec![
                Gap {
                    from_ms: base * MINUTE_MS,
                    to_ms: (base + 3) * MINUTE_MS,
                    dropped: 6,
                    dropped_bypass: 0,
                    write_errors: 0,
                },
                Gap {
                    from_ms: (base + 5) * MINUTE_MS,
                    to_ms: (base + 6) * MINUTE_MS,
                    dropped: 2,
                    dropped_bypass: 0,
                    write_errors: 0,
                },
            ]
        );
    }

    #[test]
    fn at_most_fifty_of_the_newest_gaps_are_reported() {
        let shared = Shared::default();
        let base = now() / MINUTE_MS - 200;
        for index in 0..60 {
            // Every other minute, so no two losses merge.
            shared.lose(
                (base + 2 * index) * MINUTE_MS,
                Loss {
                    write_errors: 1,
                    ..Loss::default()
                },
            );
        }
        let gaps = shared.gaps_at(base + 200);
        assert_eq!(gaps.len(), GAPS_MAX);
        assert_eq!(gaps[0].from_ms, (base + 2 * 10) * MINUTE_MS);
        assert_eq!(gaps[GAPS_MAX - 1].from_ms, (base + 2 * 59) * MINUTE_MS);
    }

    #[test]
    fn a_gap_carries_exactly_the_five_documented_keys() {
        let gap = Gap {
            from_ms: 60_000,
            to_ms: 120_000,
            dropped: 37,
            dropped_bypass: 2,
            write_errors: 1,
        };
        let value = serde_json::to_value(gap).expect("json");
        let keys: std::collections::BTreeSet<&str> = value
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "from_ms",
                "to_ms",
                "dropped",
                "dropped_bypass",
                "write_errors",
            ])
        );
        assert_eq!(value["dropped_bypass"], 2);
    }

    #[test]
    fn losses_older_than_a_day_are_forgotten() {
        let shared = Shared::default();
        let now_minute = now() / MINUTE_MS;
        shared.lose(
            (now_minute - LOSS_MINUTES - 1) * MINUTE_MS,
            Loss {
                dropped: 1,
                ..Loss::default()
            },
        );
        assert!(shared.gaps_at(now_minute).is_empty());
    }

    #[test]
    fn the_jev_columns_name_the_likeliest_answers() {
        let jev = JevRecord {
            access: BTreeMap::from([
                ("ALLOW".to_owned(), 0.2),
                ("DENY".to_owned(), 0.7),
                ("UNKNOWN".to_owned(), 0.1),
            ]),
            attack: BTreeMap::from([("ATTACK".to_owned(), 0.6), ("BENIGN".to_owned(), 0.4)]),
            ..JevRecord::default()
        };
        assert_eq!(top_option(&jev.access).as_deref(), Some("DENY"));
        assert_eq!(top_option(&jev.attack).as_deref(), Some("ATTACK"));
        assert_eq!(confidence(&jev), Some(0.6));
        assert_eq!(confidence(&JevRecord::default()), None);
    }
}
