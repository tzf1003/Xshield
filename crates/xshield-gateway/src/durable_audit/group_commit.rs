//! Group commit for the durable-audit journal.
//!
//! Every request appends to the journal twice (admission, then terminal) and
//! each append must be durable before the request goes on. With one `fsync` per
//! append, serialized by the journal mutex, an edge handled at most
//! `1 / fsync_latency` requests per second whatever the concurrency, and every
//! queued request paid for the ones ahead of it. Measured on one macOS laptop
//! (`scripts/bench_gateway.py`): about 8 ms and 130 requests/s with the journal
//! on the SSD against 0.4 ms and 2,000+ requests/s on a RAM disk.
//!
//! One writer thread now takes every commit that is waiting, appends them in
//! arrival order without syncing, makes them all durable with a single sync, and
//! only then answers each caller. The guarantee a caller relied on is unchanged:
//! a receipt is released only after its bytes are durable, and nothing is
//! forwarded before that. What changes is that concurrent commits share the sync.
//!
//! Failure rules, each pinned by a test:
//! * A batch the journal refuses before writing (quota, bad event) fails alone;
//!   the rest of its group is unaffected.
//! * A write or sync error poisons the journal handle. Every batch appended
//!   since the last successful sync is then of unknown durability, so every one
//!   of them is answered with an error and the barrier closes; the first one
//!   carries the root cause, the others report a poisoned journal.
//! * The writer never answers before the journal lock is released.

use super::{BatchContext, DurableAuditError, PendingEvent, append_events_with};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};
use tokio::sync::oneshot;
use xshield_audit::{JournalError, JournalReceipt, LocalJournal};

/// Upper bound on the commits one sync may cover. It only bounds how long the
/// journal lock is held and how much memory one group needs; a request waits at
/// most for the group in progress plus its own.
const MAX_GROUP_COMMITS: usize = 256;

/// Which tenant, site, policy and producer an append is recorded for. A scoped
/// `DurableAudit` shares the journal but not the scope, so it travels with the
/// commit rather than living in the writer.
pub(super) struct AuditScope {
    pub(super) tenant_id: String,
    pub(super) site_id: String,
    pub(super) policy_revision: String,
    pub(super) producer_id: String,
}

struct Commit {
    scope: AuditScope,
    context: BatchContext,
    events: Vec<PendingEvent>,
    reply: oneshot::Sender<Result<Vec<JournalReceipt>, DurableAuditError>>,
}

/// Counters for tests and, later, a health view. Relaxed ordering is enough:
/// nothing synchronizes on them.
#[derive(Default)]
pub(super) struct CommitStats {
    enqueued: AtomicU64,
    commits: AtomicU64,
    syncs: AtomicU64,
    largest_group: AtomicU64,
}

#[cfg(test)]
impl CommitStats {
    /// `(commits queued, commits answered, syncs performed, commits in the largest group)`.
    pub(super) fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.enqueued.load(Ordering::Relaxed),
            self.commits.load(Ordering::Relaxed),
            self.syncs.load(Ordering::Relaxed),
            self.largest_group.load(Ordering::Relaxed),
        )
    }
}

/// The single writer. Dropping the last handle closes the queue and joins the
/// thread, so the journal is closed again by the time the drop returns.
pub(super) struct GroupCommit {
    sender: Option<mpsc::Sender<Commit>>,
    writer: Option<JoinHandle<()>>,
    // Read through `stats()`, which only the tests use until a health view does.
    #[cfg_attr(not(test), allow(dead_code))]
    stats: Arc<CommitStats>,
}

impl GroupCommit {
    /// Starts the writer over a shared journal slot.
    ///
    /// # Errors
    /// [`DurableAuditError::Journal`] when the operating system refuses the thread.
    pub(super) fn start(
        journal: Arc<Mutex<Option<LocalJournal>>>,
    ) -> Result<Self, DurableAuditError> {
        let (sender, receiver) = mpsc::channel();
        let stats = Arc::new(CommitStats::default());
        let counters = Arc::clone(&stats);
        let writer = thread::Builder::new()
            .name("xshield-audit-writer".to_owned())
            .spawn(move || run(&journal, &receiver, &counters))
            .map_err(|error| DurableAuditError::Journal(JournalError::Io(error)))?;
        Ok(Self {
            sender: Some(sender),
            writer: Some(writer),
            stats,
        })
    }

    /// Queues one batch and waits until it is durable (or has failed).
    ///
    /// Cancelling the future does not cancel the commit: a queued batch is
    /// still written, exactly as a blocking append that outlived its request
    /// always was.
    ///
    /// # Errors
    /// The batch's own refusal, the shared sync failure, or
    /// [`DurableAuditError::Unavailable`] when the writer is gone.
    pub(super) async fn commit(
        &self,
        scope: AuditScope,
        context: BatchContext,
        events: Vec<PendingEvent>,
    ) -> Result<Vec<JournalReceipt>, DurableAuditError> {
        let sender = self.sender.as_ref().ok_or(DurableAuditError::Unavailable)?;
        let (reply, answer) = oneshot::channel();
        sender
            .send(Commit {
                scope,
                context,
                events,
                reply,
            })
            .map_err(|_| DurableAuditError::Unavailable)?;
        self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
        answer.await.unwrap_or(Err(DurableAuditError::Unavailable))
    }

    #[cfg(test)]
    pub(super) fn stats(&self) -> &CommitStats {
        &self.stats
    }
}

impl Drop for GroupCommit {
    fn drop(&mut self) {
        // Closing the queue ends the writer after it has answered what it holds.
        drop(self.sender.take());
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

fn run(
    journal: &Mutex<Option<LocalJournal>>,
    receiver: &mpsc::Receiver<Commit>,
    stats: &CommitStats,
) {
    while let Ok(first) = receiver.recv() {
        let mut group = vec![first];
        while group.len() < MAX_GROUP_COMMITS {
            match receiver.try_recv() {
                Ok(next) => group.push(next),
                Err(_) => break,
            }
        }
        commit_group(journal, group, stats);
    }
}

fn fail_all(group: Vec<Commit>, error: fn() -> DurableAuditError) {
    for commit in group {
        let _ = commit.reply.send(Err(error()));
    }
}

fn commit_group(journal: &Mutex<Option<LocalJournal>>, group: Vec<Commit>, stats: &CommitStats) {
    let size = u64::try_from(group.len()).unwrap_or(u64::MAX);
    let Ok(mut slot) = journal.lock() else {
        fail_all(group, || DurableAuditError::LockPoisoned);
        return;
    };
    let Some(journal) = slot.as_mut() else {
        fail_all(group, || DurableAuditError::Unavailable);
        return;
    };
    let mut appended = Vec::with_capacity(group.len());
    for commit in group {
        let Commit {
            scope,
            context,
            events,
            reply,
        } = commit;
        let result = append_events_with(
            journal,
            &scope.tenant_id,
            &scope.site_id,
            &scope.policy_revision,
            &scope.producer_id,
            &context,
            &events,
            LocalJournal::append_batch_unsynced,
        );
        appended.push((reply, result));
    }
    // One sync for everything above. A group in which no batch was written
    // (all refused) has nothing to make durable and costs nothing, which the
    // journal's own counter reflects.
    let syncs_before = journal.sync_count();
    let synced = journal.sync();
    let syncs_made = journal.sync_count().saturating_sub(syncs_before);
    drop(slot);
    stats.commits.fetch_add(size, Ordering::Relaxed);
    stats.syncs.fetch_add(syncs_made, Ordering::Relaxed);
    stats.largest_group.fetch_max(size, Ordering::Relaxed);

    let sync_failed = synced.is_err();
    let mut root_cause = synced.err();
    for (reply, result) in appended {
        let outcome = match result {
            Err(error) => Err(error),
            Ok(receipts) if !sync_failed => Ok(receipts),
            // Appended but never confirmed durable: unknown, so failed.
            Ok(_) => Err(DurableAuditError::Journal(
                root_cause.take().unwrap_or(JournalError::Poisoned),
            )),
        };
        let _ = reply.send(outcome);
    }
}
