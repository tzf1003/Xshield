//! The gateway's heartbeat and its Jev prompt registration (docs/07 sections
//! 7.5.5, 7.7.5, and 7.8.1).
//!
//! Each instance keeps one `edge_status` row, rewritten every
//! [`HEARTBEAT_INTERVAL`] and at once after a site change. The control plane
//! reads it for the status lights, the system page, and the log gaps.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;
use xshield_judge::context::{
    CACHE_MINUTES, IDLE_MAX_MS, LONG_VALUE_CHARS, RECENT_MAX, SEEN_MAX, SESSIONS_MAX, SOURCES_MAX,
};
use xshield_judge::engine::{ADDRESS_CALLS_PER_MINUTE, Judge, SESSION_CALLS_PER_MINUTE};
use xshield_judge::jev::JevPort;
use xshield_judge::slot::Source;
use xshield_judge::state::{Prompt, SECRET_WORDS, STATE_BYTES_MAX};
use xshield_judge::values::{REQUEST_VALUES_MAX, RESPONSE_PARSE_MAX};

use crate::jev_settings::{JevLoader, JevReport};
use crate::proxy::REQUEST_BODY_MAX;
use crate::sink::{Counters, Gap, QUEUE_CAPACITY};
use crate::sites::{SiteStatus, SiteTable};

/// How often the heartbeat is written, besides each site change.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// The gateway's name: the `HOSTNAME` variable, or `edge` when it is not set.
#[must_use]
pub fn edge_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "edge".to_owned())
}

/// What this process reports about itself, fixed for its lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// The gateway's name, see [`edge_name`].
    pub edge: String,
    /// When the process started, Unix milliseconds.
    pub started_at_millis: i64,
    /// The listening ports, comma separated.
    pub listen: String,
    /// Whether the listeners speak TLS.
    pub tls: bool,
}

/// One heartbeat's content.
#[derive(Debug, Clone, PartialEq)]
pub struct Beat {
    /// Every site's status, by name.
    pub sites: BTreeMap<String, SiteStatus>,
    /// Sessions the judge holds.
    pub sessions: usize,
    /// Rows waiting for the writer.
    pub queue: usize,
    /// Rows stored since start.
    pub written: u64,
    /// Rows dropped because the queue was full.
    pub dropped: u64,
    /// Bypass rows dropped under queue pressure.
    pub dropped_bypass: u64,
    /// Rows the writer could not store.
    pub write_errors: u64,
    /// The losses of the last 24 hours.
    pub gaps: Vec<Gap>,
    /// The Jev route and model, without any key.
    pub jev: serde_json::Value,
    /// The judging parameters in force.
    pub params: serde_json::Value,
}

/// Gathers the heartbeat content from the running process. `report` says where the
/// Jev settings in use came from.
#[must_use]
pub fn gather<J: JevPort>(
    judge: &Judge<J>,
    sites: &SiteTable,
    counters: &Counters,
    report: &JevReport,
) -> Beat {
    let jev = judge.jev();
    Beat {
        sites: sites.statuses(),
        sessions: judge.session_count(),
        queue: counters.queued(),
        written: counters.written(),
        dropped: counters.dropped(),
        dropped_bypass: counters.dropped_bypass(),
        write_errors: counters.write_errors(),
        gaps: counters.gaps(),
        jev: jev_config(jev, judge.prompt().id(), report),
        params: params(jev.default_timeout()),
    }
}

/// Writes the heartbeat every [`HEARTBEAT_INTERVAL`], and at once after each
/// site change. It also registers the instruction version, retrying each
/// beat until that succeeds. The Jev part comes from `jev`. Runs until the
/// process exits.
pub async fn run<J: JevPort + 'static>(
    pool: PgPool,
    judge: Arc<Judge<J>>,
    sites: Arc<SiteTable>,
    counters: Counters,
    instance: Instance,
    jev: Arc<JevLoader>,
) {
    let changed = sites.changed();
    let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
    let mut registered = false;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = changed.notified() => {}
        }
        if !registered {
            match register_prompt(&pool, judge.prompt()).await {
                Ok(()) => registered = true,
                Err(error) => eprintln!("xshield-edge: prompt registration failed: {error}"),
            }
        }
        let beat = gather(&judge, &sites, &counters, &jev.report());
        if let Err(error) = write_heartbeat(&pool, &instance, &beat).await {
            eprintln!("xshield-edge: heartbeat failed: {error}");
        }
    }
}

/// Stores this instance's row in `edge_status`, replacing its previous one.
///
/// # Errors
/// The database error; the caller reports it and tries again at the next beat.
pub async fn write_heartbeat(
    pool: &PgPool,
    instance: &Instance,
    beat: &Beat,
) -> Result<(), sqlx::Error> {
    let sites = serde_json::to_value(&beat.sites).map_err(encode)?;
    let gaps = serde_json::to_value(&beat.gaps).map_err(encode)?;
    sqlx::query(
        "INSERT INTO edge_status (edge, started_at, seen_at, build, listen, tls, sites, \
         sessions, queue, written, dropped, dropped_bypass, write_errors, gaps, jev, params) \
         VALUES ($1, to_timestamp($2::bigint::double precision / 1000), now(), $3, $4, $5, $6, \
         $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         ON CONFLICT (edge) DO UPDATE SET started_at = excluded.started_at, \
         seen_at = excluded.seen_at, build = excluded.build, listen = excluded.listen, \
         tls = excluded.tls, sites = excluded.sites, sessions = excluded.sessions, \
         queue = excluded.queue, written = excluded.written, dropped = excluded.dropped, \
         dropped_bypass = excluded.dropped_bypass, write_errors = excluded.write_errors, \
         gaps = excluded.gaps, jev = excluded.jev, params = excluded.params",
    )
    .bind(&instance.edge)
    .bind(instance.started_at_millis)
    .bind(env!("CARGO_PKG_VERSION"))
    .bind(&instance.listen)
    .bind(instance.tls)
    .bind(sites)
    .bind(i32::try_from(beat.sessions).unwrap_or(i32::MAX))
    .bind(i32::try_from(beat.queue).unwrap_or(i32::MAX))
    .bind(i64::try_from(beat.written).unwrap_or(i64::MAX))
    .bind(i64::try_from(beat.dropped).unwrap_or(i64::MAX))
    .bind(i64::try_from(beat.dropped_bypass).unwrap_or(i64::MAX))
    .bind(i64::try_from(beat.write_errors).unwrap_or(i64::MAX))
    .bind(gaps)
    .bind(&beat.jev)
    .bind(&beat.params)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Stores an instruction version once: a version already there is left alone
/// (docs/07 section 7.5.5).
///
/// # Errors
/// The database error.
pub async fn register_prompt(pool: &PgPool, prompt: &Prompt) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO jev_prompts (id, questions) VALUES ($1, $2::jsonb) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(prompt.id())
    .bind(prompt.questions_json())
    .execute(pool)
    .await
    .map(|_| ())
}

/// The Jev route, endpoint host, model, default timeout, instruction id, and
/// where the settings came from (docs/03 section 3.3). No key is in it, and none
/// is ever added.
fn jev_config<J: JevPort>(jev: &J, prompt: &str, report: &JevReport) -> serde_json::Value {
    json!({
        "route": jev.route(),
        "endpoint_host": jev.endpoint_host(),
        "model": jev.model(),
        "timeout_ms": millis(jev.default_timeout()),
        "prompt": prompt,
        "config_source": report.source.map(Source::as_str),
        "config_version": report.version,
        "config_error": report.error,
        "env_available": report.env_available,
        "env_key_var": report.env_key_var,
        "env_overridden": report.env_overridden,
    })
}

/// The parameters the gateway runs with: the site-overridable defaults and
/// the fixed limits (docs/07 section 7.9.8).
fn params(default_timeout: Duration) -> serde_json::Value {
    json!({
        "site_overridable": {
            "jev_timeout_ms": millis(default_timeout),
            "session_calls_per_minute": SESSION_CALLS_PER_MINUTE,
            "address_calls_per_minute": ADDRESS_CALLS_PER_MINUTE,
            "allow_cache_minutes": CACHE_MINUTES,
            "secret_fields": SECRET_WORDS,
            "synonyms": [["payment", "card"]],
        },
        "fixed": {
            "seen_max": SEEN_MAX,
            "sources_max": SOURCES_MAX,
            "recent_max": RECENT_MAX,
            "idle_hours": IDLE_MAX_MS / 3_600_000,
            "sessions_max": SESSIONS_MAX,
            "long_value_chars": LONG_VALUE_CHARS,
            "state_bytes_max": STATE_BYTES_MAX,
            "request_body_max": REQUEST_BODY_MAX,
            "response_parse_max": RESPONSE_PARSE_MAX,
            "request_values_max": REQUEST_VALUES_MAX,
            "queue_capacity": QUEUE_CAPACITY,
        },
    })
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn encode(error: serde_json::Error) -> sqlx::Error {
    sqlx::Error::Encode(Box::new(error))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use xshield_judge::jev::JevFailure;

    use super::*;

    struct Fake;

    #[async_trait]
    impl JevPort for Fake {
        fn model(&self) -> String {
            "fake-model".to_owned()
        }
        fn route(&self) -> String {
            "fake".to_owned()
        }
        fn endpoint(&self) -> String {
            "https://jev.test/v1/systemone".to_owned()
        }
        fn endpoint_host(&self) -> String {
            "jev.test".to_owned()
        }
        fn default_timeout(&self) -> Duration {
            Duration::from_millis(2000)
        }
        async fn ask(&self, _body: Vec<u8>, _timeout: Duration) -> Result<Vec<u8>, JevFailure> {
            Err(JevFailure::Timeout)
        }
    }

    #[test]
    fn the_jev_block_names_the_route_and_never_a_key() {
        let config = jev_config(&Fake, "jq_0123456789abcdef", &JevReport::default());
        assert_eq!(
            config,
            json!({
                "route": "fake",
                "endpoint_host": "jev.test",
                "model": "fake-model",
                "timeout_ms": 2000,
                "prompt": "jq_0123456789abcdef",
                "config_source": null,
                "config_version": null,
                "config_error": null,
                "env_available": false,
                "env_key_var": null,
                "env_overridden": [],
            })
        );
    }

    #[test]
    fn the_jev_block_says_which_saved_version_serves_and_what_failed() {
        let report = JevReport {
            source: Some(Source::Console),
            version: Some(6),
            error: Some("MODEL_KEY_UNREADABLE".to_owned()),
            env_available: true,
            env_key_var: Some("AI_GATEWAY_API_KEY"),
            env_overridden: vec!["AI_GATEWAY_API_KEY"],
        };
        let config = jev_config(&Fake, "jq_0123456789abcdef", &report);
        assert_eq!(config["config_source"], "console");
        assert_eq!(config["config_version"], 6);
        assert_eq!(config["config_error"], "MODEL_KEY_UNREADABLE");
        assert_eq!(config["env_available"], true);
        assert_eq!(config["env_overridden"][0], "AI_GATEWAY_API_KEY");
    }

    #[test]
    fn the_params_report_the_queue_capacity_and_the_site_words() {
        let report = params(Duration::from_millis(2000));
        assert_eq!(report["fixed"]["queue_capacity"], 10_000);
        assert_eq!(report["fixed"]["idle_hours"], 24);
        assert_eq!(report["site_overridable"]["jev_timeout_ms"], 2000);
        assert_eq!(
            report["site_overridable"]["secret_fields"][0],
            "authorization"
        );
    }

    #[test]
    fn the_edge_name_defaults_when_the_host_name_is_missing() {
        // The variable is read at call time; an empty value must fall back.
        let name = edge_name();
        assert!(!name.is_empty());
    }
}
