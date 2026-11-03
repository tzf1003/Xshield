//! The gateway's Jev slot: the client the judge calls. Its settings can change
//! while the process runs, when the console saves a new version (docs/03
//! section 3.3, docs/07 section 7.7).
//!
//! A new version that fails to load does not replace the one in use. The failure
//! code is kept for the heartbeat, and the client in use keeps judging. Nothing
//! loaded at all is a state of its own: calls fail with
//! [`JevFailure::NotConfigured`], which the gateway treats as an unavailable Jev
//! (docs/02 section 2.3).

use std::sync::Arc;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use async_trait::async_trait;

use crate::jev::{JevClient, JevFailure, JevPort, TIMEOUT};

/// Where the settings in use came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The console's model page.
    Console,
    /// The gateway's environment.
    Env,
}

impl Source {
    /// The name the heartbeat and the console show.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Console => "console",
            Self::Env => "env",
        }
    }
}

/// What the gateway reports about its Jev configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigStatus {
    /// Where the calls take their settings from; `None` while nothing is loaded.
    pub source: Option<Source>,
    /// The console version in use; `None` for the environment and for nothing.
    pub version: Option<i64>,
    /// The stable code of the newest load failure. The configuration in use, if
    /// any, keeps serving while this is set.
    pub error: Option<String>,
}

struct Active {
    client: Arc<JevClient>,
    source: Source,
    version: Option<i64>,
}

#[derive(Default)]
struct SlotState {
    active: Option<Active>,
    error: Option<String>,
}

/// The Jev client in use, swapped when the settings change.
#[derive(Default)]
pub struct JevSlot {
    state: RwLock<SlotState>,
}

impl JevSlot {
    /// An empty slot: nothing is loaded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `client` the one in use and clears the last failure.
    pub fn install(&self, source: Source, version: Option<i64>, client: JevClient) {
        let mut state = self.write();
        state.active = Some(Active {
            client: Arc::new(client),
            source,
            version,
        });
        state.error = None;
    }

    /// Records a failed load with its stable code. The configuration in use keeps serving.
    pub fn fail(&self, code: &str) {
        self.write().error = Some(code.to_owned());
    }

    /// Drops the configuration in use: nothing is loaded any more.
    pub fn clear(&self) {
        let mut state = self.write();
        state.active = None;
        state.error = None;
    }

    /// What the gateway reports about its configuration.
    #[must_use]
    pub fn status(&self) -> ConfigStatus {
        let state = self.read();
        ConfigStatus {
            source: state.active.as_ref().map(|active| active.source),
            version: state.active.as_ref().and_then(|active| active.version),
            error: state.error.clone(),
        }
    }

    /// The source and version of the configuration in use, if any.
    #[must_use]
    pub fn in_use(&self) -> Option<(Source, Option<i64>)> {
        self.read()
            .active
            .as_ref()
            .map(|active| (active.source, active.version))
    }

    fn client(&self) -> Option<Arc<JevClient>> {
        self.read()
            .active
            .as_ref()
            .map(|active| Arc::clone(&active.client))
    }

    fn read(&self) -> RwLockReadGuard<'_, SlotState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, SlotState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl JevPort for JevSlot {
    fn model(&self) -> String {
        self.client()
            .map(|client| client.model())
            .unwrap_or_default()
    }

    fn route(&self) -> String {
        self.client()
            .map_or_else(|| "none".to_owned(), |client| client.route())
    }

    fn endpoint(&self) -> String {
        self.client()
            .map(|client| client.endpoint())
            .unwrap_or_default()
    }

    fn endpoint_host(&self) -> String {
        self.client()
            .map(|client| client.endpoint_host())
            .unwrap_or_default()
    }

    fn default_timeout(&self) -> Duration {
        self.client()
            .map_or(TIMEOUT, |client| client.default_timeout())
    }

    async fn ask(&self, body: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, JevFailure> {
        match self.client() {
            Some(client) => client.ask(body, timeout).await,
            None => Err(JevFailure::NotConfigured),
        }
    }
}

/// A shared port is a port: the gateway's judge and its settings loader hold the
/// same slot.
#[async_trait]
impl<T: JevPort> JevPort for Arc<T> {
    fn model(&self) -> String {
        (**self).model()
    }

    fn route(&self) -> String {
        (**self).route()
    }

    fn endpoint(&self) -> String {
        (**self).endpoint()
    }

    fn endpoint_host(&self) -> String {
        (**self).endpoint_host()
    }

    fn default_timeout(&self) -> Duration {
        (**self).default_timeout()
    }

    async fn ask(&self, body: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, JevFailure> {
        (**self).ask(body, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jev::JevClient;

    fn client(model: &str) -> JevClient {
        JevClient::new(
            "https://jev.internal/v1/systemone",
            "sk-test-1234",
            model,
            TIMEOUT,
        )
        .expect("a valid client")
    }

    #[tokio::test]
    async fn an_empty_slot_fails_calls_as_not_configured() {
        let slot = JevSlot::new();
        assert_eq!(slot.route(), "none");
        assert_eq!(slot.model(), "");
        assert_eq!(
            slot.ask(vec![], TIMEOUT).await,
            Err(JevFailure::NotConfigured)
        );
        assert_eq!(slot.status(), ConfigStatus::default());
    }

    #[test]
    fn an_installed_client_replaces_the_last_one_and_clears_the_failure() {
        let slot = JevSlot::new();
        slot.install(Source::Env, None, client("jev-env"));
        assert_eq!(slot.model(), "jev-env");
        slot.fail("MODEL_KEY_UNREADABLE");
        assert_eq!(slot.status().error.as_deref(), Some("MODEL_KEY_UNREADABLE"));
        slot.install(Source::Console, Some(6), client("jev-console"));
        assert_eq!(slot.model(), "jev-console");
        assert_eq!(
            slot.status(),
            ConfigStatus {
                source: Some(Source::Console),
                version: Some(6),
                error: None,
            }
        );
        assert_eq!(slot.in_use(), Some((Source::Console, Some(6))));
    }

    #[test]
    fn a_failed_newer_version_keeps_the_one_in_use() {
        let slot = JevSlot::new();
        slot.install(Source::Console, Some(5), client("jev-5"));
        slot.fail("JEV_CONFIG_ENDPOINT_INVALID");
        assert_eq!(slot.model(), "jev-5");
        let status = slot.status();
        assert_eq!(status.version, Some(5));
        assert_eq!(status.error.as_deref(), Some("JEV_CONFIG_ENDPOINT_INVALID"));
    }

    #[test]
    fn clearing_drops_the_configuration_in_use() {
        let slot = JevSlot::new();
        slot.install(Source::Env, None, client("jev-env"));
        slot.clear();
        assert_eq!(slot.route(), "none");
        assert_eq!(slot.status(), ConfigStatus::default());
    }

    #[test]
    fn the_source_names_are_the_heartbeat_names() {
        assert_eq!(Source::Console.as_str(), "console");
        assert_eq!(Source::Env.as_str(), "env");
    }
}
