//! Resident mode for the batch binaries (`xshield-worker`,
//! `xshield-outbox-worker`, `xshield-audit-seal`).
//!
//! Each of them does one bounded, resumable pass and exits, which suits cron.
//! Orchestrators without a cron (a Compose service, a Kubernetes Deployment)
//! need a process that stays up instead. With `XSHIELD_RUN_INTERVAL_SECONDS`
//! set, the binary repeats its pass, waiting that long between passes; a
//! failed pass is reported and retried on the next tick rather than ending the
//! process. Every pass is already safe to interrupt (leases expire,
//! checkpoints and manifests are replaced by rename), so the default `SIGTERM`
//! is a clean stop.
//!
//! A process that stays up while every pass fails would look healthy to an
//! orchestrator, so after each successful pass the current Unix time is
//! written to the file named by `XSHIELD_RUN_HEARTBEAT_FILE`; a probe compares
//! its age with the interval.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds between passes; unset means one pass, as before.
pub const INTERVAL_VARIABLE: &str = "XSHIELD_RUN_INTERVAL_SECONDS";
/// File rewritten with the Unix time after each successful pass.
pub const HEARTBEAT_VARIABLE: &str = "XSHIELD_RUN_HEARTBEAT_FILE";
/// Longest accepted interval: one day.
pub const MAX_INTERVAL_SECONDS: u64 = 86_400;

/// A resident-mode setting that cannot be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleError(&'static str);

impl fmt::Display for ScheduleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ScheduleError {}

/// How a batch binary repeats its pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Schedule {
    interval: Option<Duration>,
    heartbeat: Option<PathBuf>,
}

impl Schedule {
    /// Reads the schedule from the process environment.
    ///
    /// # Errors
    ///
    /// [`ScheduleError`] when the interval is not a whole number of seconds
    /// from 1 to one day, or a heartbeat file is named without an interval.
    pub fn from_env() -> Result<Self, ScheduleError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    fn from_lookup(
        lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Self, ScheduleError> {
        let interval = match lookup(INTERVAL_VARIABLE) {
            None => None,
            Some(value) => {
                let seconds = value
                    .to_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|seconds| (1..=MAX_INTERVAL_SECONDS).contains(seconds))
                    .ok_or(ScheduleError(
                        "XSHIELD_RUN_INTERVAL_SECONDS must be a whole number from 1 to 86400",
                    ))?;
                Some(Duration::from_secs(seconds))
            }
        };
        let heartbeat = lookup(HEARTBEAT_VARIABLE)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        if heartbeat.is_some() && interval.is_none() {
            return Err(ScheduleError(
                "XSHIELD_RUN_HEARTBEAT_FILE needs XSHIELD_RUN_INTERVAL_SECONDS",
            ));
        }
        Ok(Self {
            interval,
            heartbeat,
        })
    }

    /// The wait between passes, or `None` for a single pass.
    #[must_use]
    pub const fn interval(&self) -> Option<Duration> {
        self.interval
    }

    /// Records a successful pass in the heartbeat file, if one is configured.
    ///
    /// # Errors
    ///
    /// The I/O error of writing or renaming the file.
    pub fn record_success(&self) -> std::io::Result<()> {
        let Some(path) = &self.heartbeat else {
            return Ok(());
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        write_heartbeat(path, now)
    }
}

fn write_heartbeat(path: &Path, now: u64) -> std::io::Result<()> {
    // Written beside the target and renamed, so a probe never reads half.
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    std::fs::write(&temporary, format!("{now}\n"))?;
    std::fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn schedule(pairs: &[(&str, &str)]) -> Result<Schedule, ScheduleError> {
        let map: HashMap<&str, OsString> = pairs
            .iter()
            .map(|(name, value)| (*name, OsString::from(value)))
            .collect();
        Schedule::from_lookup(|name| map.get(name).cloned())
    }

    #[test]
    fn a_pass_repeats_only_when_an_interval_is_set() {
        assert_eq!(schedule(&[]).unwrap().interval(), None);
        assert_eq!(
            schedule(&[(INTERVAL_VARIABLE, "30")]).unwrap().interval(),
            Some(Duration::from_secs(30))
        );
        for refused in ["0", "86401", "-1", "1.5", " 30", ""] {
            assert!(
                schedule(&[(INTERVAL_VARIABLE, refused)]).is_err(),
                "{refused:?}"
            );
        }
        assert!(schedule(&[(HEARTBEAT_VARIABLE, "/tmp/beat")]).is_err());
        // A one-shot run has nothing to record.
        assert_eq!(schedule(&[]).unwrap().record_success().ok(), Some(()));
    }

    #[test]
    fn the_heartbeat_is_replaced_whole() {
        let directory = std::env::temp_dir().join(format!(
            "xshield-resident-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("heartbeat");
        write_heartbeat(&path, 7).unwrap();
        write_heartbeat(&path, 1_700_000_000).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "1700000000\n");
        let configured = schedule(&[
            (INTERVAL_VARIABLE, "5"),
            (HEARTBEAT_VARIABLE, path.to_str().unwrap()),
        ])
        .unwrap();
        configured.record_success().unwrap();
        let written: u64 = std::fs::read_to_string(&path)
            .unwrap()
            .trim_end()
            .parse()
            .unwrap();
        assert!(written > 1_700_000_000);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
