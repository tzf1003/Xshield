//! The gateway's Jev settings over time (docs/03 section 3.3, docs/07 section 7.7).
//!
//! While the console holds a key for Jev, the settings it saved are the ones the
//! calls use. Without one, the gateway reads its environment, as it always has. The
//! console is read every [`REFRESH_INTERVAL`], the same cadence as the sites. A new
//! version that fails to load leaves the one in use serving, and its failure code
//! goes into the heartbeat. With nothing loaded at all the gateway still starts;
//! judgements report `JEV_NOT_CONFIGURED` until a key is supplied.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use xshield_judge::jev::{EnvSettings, JevClient};
use xshield_judge::slot::{JevSlot, Source};
use xshield_postgres::key_seal::KeySealer;
use xshield_postgres::model_config_store::{JevSecret, load_jev};

/// How often the console's Jev settings are read, as often as the sites are.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// What the heartbeat reports about the Jev configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JevReport {
    /// Where the calls take their settings from; `None` while nothing is loaded.
    pub source: Option<Source>,
    /// The console version in use; `None` for the environment and for nothing.
    pub version: Option<i64>,
    /// The code of the newest load failure. The configuration in use, if any, keeps
    /// serving while this is set.
    pub error: Option<String>,
    /// Whether the environment holds a usable configuration.
    pub env_available: bool,
    /// The environment variable the key comes from for the route the environment
    /// names, whether or not it is set. Its name only.
    pub env_key_var: Option<&'static str>,
    /// The Jev variables that are set while the console's configuration is in use.
    /// They have no effect then. Names only, never values.
    pub env_overridden: Vec<&'static str>,
}

/// Keeps the gateway's Jev slot in step with the console and the environment.
pub struct JevLoader {
    slot: Arc<JevSlot>,
    env: EnvSettings,
    sealer: KeySealer,
}

impl JevLoader {
    /// A loader that fills `slot`. `env` is the environment as read at start-up, and
    /// `sealer` opens the keys the console stores.
    #[must_use]
    pub fn new(slot: Arc<JevSlot>, env: EnvSettings, sealer: KeySealer) -> Self {
        Self { slot, env, sealer }
    }

    /// Installs the environment's configuration when it is usable. Called once before
    /// the gateway serves, so judgements do not wait for the first console read.
    pub fn start(&self) {
        if let Err(code) = self.install_environment() {
            self.record(&code);
        }
    }

    /// Reads the console's saved settings and applies them.
    pub async fn refresh(&self, pool: &PgPool) {
        match load_jev(pool, Some(&self.sealer)).await {
            Ok(Some(secret)) => self.install_console(&secret),
            Ok(None) => {
                if let Err(code) = self.install_environment() {
                    self.record(&code);
                }
            }
            Err(error) => self.keep_or_fall_back(error.code()),
        }
    }

    /// Refreshes every [`REFRESH_INTERVAL`] until the process exits.
    pub async fn run(self: Arc<Self>, pool: PgPool) {
        let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
        loop {
            ticker.tick().await;
            self.refresh(&pool).await;
        }
    }

    /// What the heartbeat reports about the configuration.
    #[must_use]
    pub fn report(&self) -> JevReport {
        let status = self.slot.status();
        let console_in_use = status.source == Some(Source::Console);
        JevReport {
            source: status.source,
            version: status.version,
            error: status.error,
            env_available: matches!(self.env.loaded, Ok(Some(_))),
            env_key_var: self.env.key_var,
            env_overridden: if console_in_use {
                self.env.present.clone()
            } else {
                Vec::new()
            },
        }
    }

    fn install_console(&self, secret: &JevSecret) {
        if self.slot.in_use() == Some((Source::Console, Some(secret.version))) {
            return;
        }
        match JevClient::from_spec(&secret.spec, &secret.api_key) {
            Ok(client) => self
                .slot
                .install(Source::Console, Some(secret.version), client),
            Err(error) => self.keep_or_fall_back(&error.to_string()),
        }
    }

    /// Installs the environment's configuration, or says why it cannot be used. What
    /// is in use is dropped when the environment has nothing usable to put in its place.
    fn install_environment(&self) -> Result<(), String> {
        match &self.env.loaded {
            Ok(Some((spec, key))) => {
                if self.slot.in_use() == Some((Source::Env, None)) {
                    return Ok(());
                }
                let client = JevClient::from_spec(spec, key).map_err(|error| error.to_string())?;
                self.slot.install(Source::Env, None, client);
                Ok(())
            }
            Ok(None) => {
                self.drop_in_use();
                Ok(())
            }
            Err(error) => {
                self.drop_in_use();
                Err(error.to_string())
            }
        }
    }

    /// A version failed to load. A configuration in use keeps serving. With nothing in
    /// use, the environment serves instead. The failure is recorded either way.
    fn keep_or_fall_back(&self, code: &str) {
        if self.slot.in_use().is_none() {
            // The environment's own failure does not replace the console's code.
            let _ = self.install_environment();
        }
        self.record(code);
    }

    fn drop_in_use(&self) {
        if self.slot.in_use().is_some() {
            self.slot.clear();
        }
    }

    /// Records a failure, and logs it when it differs from the one already recorded,
    /// so a failure that persists is logged once.
    fn record(&self, code: &str) {
        if self.slot.status().error.as_deref() != Some(code) {
            eprintln!("xshield-edge: Jev settings failed to load: {code}");
        }
        self.slot.fail(code);
    }
}

#[cfg(test)]
mod tests {
    use xshield_core::model::{ApiKey, JevRoute, JevSpec};
    use xshield_judge::jev::environment_settings_from;
    use xshield_judge::slot::ConfigStatus;

    use super::*;

    fn environment_with_key() -> EnvSettings {
        environment_settings_from(|name| {
            (name == "AI_GATEWAY_API_KEY").then(|| "sk-env-1234".to_owned())
        })
    }

    fn loader(env: EnvSettings) -> (Arc<JevSlot>, JevLoader) {
        let slot = Arc::new(JevSlot::new());
        let sealer = KeySealer::from_context_secret(&[7_u8; 32]).expect("a 32-byte secret");
        let loader = JevLoader::new(Arc::clone(&slot), env, sealer);
        (slot, loader)
    }

    fn console_secret(version: i64) -> JevSecret {
        JevSecret {
            version,
            spec: JevSpec::new(JevRoute::Gateway, None, None, 2000).expect("a gateway spec"),
            api_key: ApiKey::new("sk-console-9f3a").expect("a key"),
        }
    }

    #[test]
    fn the_environment_serves_when_the_console_holds_nothing() {
        let (slot, loader) = loader(environment_with_key());
        loader.start();
        assert_eq!(slot.status().source, Some(Source::Env));
        assert!(loader.report().env_available);
        assert!(loader.report().env_overridden.is_empty());
    }

    #[test]
    fn with_no_key_anywhere_nothing_is_loaded_and_nothing_fails() {
        let (slot, loader) = loader(environment_settings_from(|_| None));
        loader.start();
        assert_eq!(slot.status(), ConfigStatus::default());
        assert!(!loader.report().env_available);
    }

    #[test]
    fn a_malformed_environment_is_reported_and_not_loaded() {
        let (slot, loader) = loader(environment_settings_from(|name| {
            (name == "XSHIELD_JEV_ROUTE").then(|| "sideways".to_owned())
        }));
        loader.start();
        assert_eq!(slot.status().source, None);
        assert_eq!(
            slot.status().error.as_deref(),
            Some("JEV_CONFIG_ROUTE_INVALID")
        );
    }

    #[test]
    fn a_console_version_replaces_the_environment_and_names_what_it_overrides() {
        let (slot, loader) = loader(environment_with_key());
        loader.start();
        loader.install_console(&console_secret(5));
        let report = loader.report();
        assert_eq!(report.source, Some(Source::Console));
        assert_eq!(report.version, Some(5));
        assert_eq!(report.env_overridden, vec!["AI_GATEWAY_API_KEY"]);
        assert!(report.env_available);
        assert_eq!(slot.in_use(), Some((Source::Console, Some(5))));
    }

    #[test]
    fn a_failed_load_keeps_the_version_in_use_and_reports_its_code() {
        let (slot, loader) = loader(environment_with_key());
        loader.start();
        loader.install_console(&console_secret(5));
        loader.keep_or_fall_back("MODEL_KEY_UNREADABLE");
        let status = slot.status();
        assert_eq!(status.source, Some(Source::Console));
        assert_eq!(status.version, Some(5));
        assert_eq!(status.error.as_deref(), Some("MODEL_KEY_UNREADABLE"));
    }

    #[test]
    fn a_failed_load_with_nothing_in_use_falls_back_to_the_environment() {
        let (slot, loader) = loader(environment_with_key());
        loader.keep_or_fall_back("MODEL_STORE_UNAVAILABLE");
        let status = slot.status();
        assert_eq!(status.source, Some(Source::Env));
        assert_eq!(status.error.as_deref(), Some("MODEL_STORE_UNAVAILABLE"));
    }

    #[test]
    fn a_reverted_console_hands_the_calls_back_to_the_environment() {
        let (slot, loader) = loader(environment_with_key());
        loader.start();
        loader.install_console(&console_secret(5));
        assert!(loader.install_environment().is_ok());
        let status = slot.status();
        assert_eq!(status.source, Some(Source::Env));
        assert_eq!(status.version, None);
        assert!(loader.report().env_overridden.is_empty());
    }
}
