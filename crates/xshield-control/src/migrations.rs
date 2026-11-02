//! Schema migrations for the control plane (docs/07-console-architecture.md
//! section 7.2.3). The SQL under `migrations/` is compiled into the binary, and
//! `xshield-control` applies the pending migrations before it serves a request.
//! The gateway runs no migrations.

use sqlx::{
    PgPool,
    migrate::{MigrateError, Migrator},
};

/// Every migration in `migrations/`, in version order, as compiled into this binary.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Applies the migrations that `pool`'s database has not recorded yet.
///
/// sqlx records each applied migration and its checksum in `_sqlx_migrations`,
/// and refuses to continue when a recorded migration has changed, is missing
/// from this binary, or failed part-way. It holds a PostgreSQL advisory lock for
/// the whole run, so instances that start together apply each migration once.
///
/// A database that already holds the baseline schema without that ledger is
/// refused at migration 1; it is not adopted silently. docs/04 section 4.2 gives
/// the one-time recipe for such a database.
///
/// # Errors
///
/// Returns the first migration that fails, and refuses to start when the ledger
/// disagrees with this binary: a recorded migration has changed, a recorded
/// migration is missing from the binary, or an earlier run left one half-applied.
pub async fn run(pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}
