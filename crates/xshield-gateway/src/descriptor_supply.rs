//! Supplies edge-managed UI-action descriptors to `PostgreSQL` before a
//! configuration serves traffic.
//!
//! A configuration that declares page issuance owns its policy revision: its
//! descriptor set and digest are a pure function of the configuration
//! (`xshield_core::edge_descriptors`), and the issuance transactions and the
//! per-request admission recheck compare against the rows written here. The
//! same idempotent write therefore runs on every path by which a
//! configuration can start serving:
//! - startup, for the bootstrap configuration (`XSHIELD_CONFIG`);
//! - a signed control-plane apply, for every site of the incoming snapshot,
//!   after it compiled and before its pending file is written;
//! - a restart, for every site of the restored persisted snapshot, before any
//!   listener is bound.
//!
//! The write never updates a row (`sync_edge_descriptors`): a revision that
//! already binds another digest, a revision that is no longer `active` and a
//! descriptor key that already means something else are conflicts, so a
//! changed descriptor set needs a new policy revision label. `Created` and
//! `Existing` are both success, which makes retries and concurrent edges with
//! the same configuration converge.
//!
//! Failure is fail-closed on every path: a refused apply leaves the serving
//! snapshot and the persisted files untouched, and a refused start binds no
//! listener. Refusals carry a stable reason and the site that caused them.
//! The writes for one snapshot share one deadline, so an unresponsive database
//! cannot hold the apply lock or startup indefinitely; a write cut off by the
//! deadline is rolled back with its transaction or, if it had already
//! committed, left as an idempotent row the next attempt reads as `Existing`.

use async_trait::async_trait;
use std::{error::Error, time::Duration};
use tokio::time::Instant;
use xshield_core::{
    audit::ReasonCode,
    domain::{PolicyRevision, SiteId},
};
use xshield_gateway::{GatewayConfig, page_actions::EdgeDescriptorSet};
use xshield_postgres::{EdgeDescriptorSync, EdgeDescriptorSyncOutcome, StoreError};

/// Longest the apply channel waits for the supply of one snapshot. Kept well
/// inside the control plane's 8-second apply request timeout, so a refusal
/// reaches the control plane instead of a transport error while the edge is
/// still working.
pub(crate) const APPLY_SUPPLY_DEADLINE: Duration = Duration::from_secs(4);
/// Longest startup waits for the supply of the bootstrap configuration or of
/// a restored snapshot; a database that is still starting gets more room than
/// a live apply, and an unresponsive one still cannot hang the edge forever.
pub(crate) const STARTUP_SUPPLY_DEADLINE: Duration = Duration::from_secs(30);

/// Port to the descriptor rows of one policy revision.
///
/// Implemented by the `PostgreSQL` runtime; tests substitute fakes. One call
/// is one transaction: the revision row is created or compared, then every
/// descriptor is inserted or compared, and nothing is ever updated.
#[async_trait]
pub(crate) trait DescriptorStore: Send + Sync {
    /// Writes `descriptors` for the tenant, site and policy revision of
    /// `config`.
    ///
    /// # Errors
    /// [`StoreError::InvalidCommand`] when the set violates the store's own
    /// bounds, any other [`StoreError`] when the database is unavailable.
    async fn sync(
        &self,
        config: &GatewayConfig,
        descriptors: &EdgeDescriptorSet,
    ) -> Result<EdgeDescriptorSyncOutcome, StoreError>;
}

#[async_trait]
impl DescriptorStore for crate::PostgresRuntime {
    async fn sync(
        &self,
        config: &GatewayConfig,
        descriptors: &EdgeDescriptorSet,
    ) -> Result<EdgeDescriptorSyncOutcome, StoreError> {
        let digest = descriptors.content_digest_hex();
        let command = EdgeDescriptorSync::new(
            config.tenant_id(),
            config.site_id(),
            config.policy_revision(),
            &digest,
            descriptors.descriptors(),
        )?;
        self.store().await?.sync_edge_descriptors(command).await
    }
}

/// Why a configuration's descriptors could not be supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SupplyRefusal {
    /// The policy revision binds another digest or is not `active`, a stored
    /// descriptor means something else, or the set exceeds the store's
    /// bounds. Retrying cannot help; the configuration needs a new policy
    /// revision label (or the stored revision must be reactivated).
    Conflict {
        /// Site whose configuration conflicts.
        site_id: SiteId,
        /// Policy revision the conflicting set was derived for.
        policy_revision: PolicyRevision,
    },
    /// No identity store is configured, the database is unreachable, or the
    /// write did not finish before the deadline. Retrying may help.
    Unavailable {
        /// Site whose descriptors were not supplied.
        site_id: SiteId,
    },
}

/// One site whose descriptors are in place.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SiteSupply {
    /// Site that was supplied.
    pub(crate) site_id: SiteId,
    /// Whether this call created the revision or found it already bound.
    pub(crate) outcome: EdgeDescriptorSyncOutcome,
}

/// Supplies every configuration that declares page issuance, in the given
/// order, stopping at the first refusal. Configurations without page
/// issuance are skipped and never need a store.
///
/// Sites supplied before a refusal keep their rows: each one only states that
/// its own policy revision means its own descriptor set, and the next attempt
/// reads it as `Existing`. Callers must not serve any of the configurations
/// after a refusal.
///
/// # Errors
/// [`SupplyRefusal`] naming the first site that conflicts or could not be
/// written before `deadline` elapsed.
pub(crate) async fn supply_descriptors<'a>(
    store: Option<&dyn DescriptorStore>,
    configs: impl IntoIterator<Item = &'a GatewayConfig>,
    deadline: Duration,
) -> Result<Vec<SiteSupply>, SupplyRefusal> {
    let deadline = Instant::now() + deadline;
    let mut supplied = Vec::new();
    for config in configs {
        let Some(descriptors) = config.edge_descriptors() else {
            continue;
        };
        let conflict = || SupplyRefusal::Conflict {
            site_id: config.site_id().clone(),
            policy_revision: config.policy_revision().clone(),
        };
        let unavailable = || SupplyRefusal::Unavailable {
            site_id: config.site_id().clone(),
        };
        // An edge started without an identity store cannot make the
        // descriptors exist, so it must not serve a page that issues them.
        let Some(store) = store else {
            return Err(unavailable());
        };
        let outcome = match tokio::time::timeout_at(deadline, store.sync(config, descriptors)).await
        {
            Ok(Ok(outcome)) => outcome,
            // The store refuses a set outside its own bounds before any SQL
            // runs; that is a property of the configuration, not an outage.
            Ok(Err(StoreError::InvalidCommand)) => return Err(conflict()),
            Ok(Err(_)) | Err(_) => return Err(unavailable()),
        };
        if !outcome.is_ready() {
            return Err(conflict());
        }
        supplied.push(SiteSupply {
            site_id: config.site_id().clone(),
            outcome,
        });
    }
    Ok(supplied)
}

/// Which configuration a startup supply is for; it only changes the message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupSource {
    /// The bootstrap configuration read from `XSHIELD_CONFIG`.
    Bootstrap,
    /// The signed snapshot restored from `XSHIELD_EDGE_SNAPSHOT_PATH`.
    PersistedSnapshot,
}

/// Supplies descriptors before the edge binds any listener. A refusal stops
/// startup with the stable reasons the bootstrap path has always used
/// (`UI_DESCRIPTOR_CONFLICT`, `IDENTITY_STORE_UNAVAILABLE`); messages name
/// non-secret identifiers only, never connection data.
///
/// # Errors
/// A startup error describing the first refusal.
pub(crate) async fn supply_before_serving<'a>(
    store: Option<&dyn DescriptorStore>,
    configs: impl IntoIterator<Item = &'a GatewayConfig>,
    source: StartupSource,
) -> Result<Vec<SiteSupply>, Box<dyn Error>> {
    supply_descriptors(store, configs, STARTUP_SUPPLY_DEADLINE)
        .await
        .map_err(|refusal| startup_refusal(&refusal, source).into())
}

fn startup_refusal(refusal: &SupplyRefusal, source: StartupSource) -> String {
    let conflict = ReasonCode::UiDescriptorConflict.as_str();
    let unavailable = ReasonCode::IdentityStoreUnavailable.as_str();
    match (refusal, source) {
        (
            SupplyRefusal::Conflict {
                policy_revision, ..
            },
            StartupSource::Bootstrap,
        ) => format!(
            "{conflict}: policy revision {} already binds other action descriptors",
            policy_revision.as_str()
        ),
        (
            SupplyRefusal::Conflict {
                site_id,
                policy_revision,
            },
            StartupSource::PersistedSnapshot,
        ) => format!(
            "{conflict}: persisted snapshot site {} policy revision {} already binds other \
             action descriptors",
            site_id.as_str(),
            policy_revision.as_str()
        ),
        (SupplyRefusal::Unavailable { .. }, StartupSource::Bootstrap) => unavailable.to_owned(),
        (SupplyRefusal::Unavailable { site_id }, StartupSource::PersistedSnapshot) => format!(
            "{unavailable}: persisted snapshot site {} cannot supply its action descriptors",
            site_id.as_str()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fake::{FakeStore, Mode, page_site},
        *,
    };
    use serde_json::json;

    fn compiled(value: &serde_json::Value) -> GatewayConfig {
        GatewayConfig::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
    }

    fn plain_site() -> GatewayConfig {
        let mut value = page_site("site_plain", 6102, "/orders");
        value["operations"] = json!([
            {"operation_id": "entry", "method": "GET", "path": "/", "admission": "PUBLIC"}
        ]);
        value.as_object_mut().unwrap().remove("sensor");
        compiled(&value)
    }

    /// A store whose bounds reject the set before any SQL runs.
    struct Oversized;

    #[async_trait]
    impl DescriptorStore for Oversized {
        async fn sync(
            &self,
            _: &GatewayConfig,
            _: &EdgeDescriptorSet,
        ) -> Result<EdgeDescriptorSyncOutcome, StoreError> {
            Err(StoreError::InvalidCommand)
        }
    }

    #[tokio::test]
    async fn a_restored_snapshot_is_supplied_site_by_site_and_converges_on_existing() {
        let store = FakeStore::new(Mode::Up);
        let first = compiled(&page_site("site_a", 6100, "/orders"));
        let second = compiled(&page_site("site_b", 6101, "/orders"));
        let plain = plain_site();
        let supplied = supply_before_serving(
            Some(&store),
            [&first, &plain, &second],
            StartupSource::PersistedSnapshot,
        )
        .await
        .unwrap();
        assert_eq!(
            supplied,
            [
                SiteSupply {
                    site_id: first.site_id().clone(),
                    outcome: EdgeDescriptorSyncOutcome::Created
                },
                SiteSupply {
                    site_id: second.site_id().clone(),
                    outcome: EdgeDescriptorSyncOutcome::Created
                },
            ]
        );
        // The digest written is the configuration's own canonical digest.
        let digest = first.edge_descriptors().unwrap().content_digest_hex();
        assert_eq!(
            store.revision("tenant_supply", "site_a", "policy-r1"),
            Some(("active", digest.clone()))
        );
        assert_eq!(store.calls()[0], format!("site_a@policy-r1#{digest}"));
        // A second start finds everything in place.
        let again = supply_before_serving(
            Some(&store),
            [&first, &second],
            StartupSource::PersistedSnapshot,
        )
        .await
        .unwrap();
        assert_eq!(again.len(), 2);
        assert!(
            again
                .iter()
                .all(|site| site.outcome == EdgeDescriptorSyncOutcome::Existing)
        );
        // Configurations without page issuance never reach the store.
        assert!(
            store
                .calls()
                .iter()
                .all(|call| !call.contains("site_plain"))
        );
    }

    #[tokio::test]
    async fn a_restart_refuses_with_the_bootstrap_reasons_and_names_the_site() {
        let drifted = compiled(&page_site("site_a", 6100, "/orders-v2"));
        let store = FakeStore::new(Mode::Up);
        store.seed(
            "tenant_supply",
            "site_a",
            "policy-r1",
            "active",
            &"e".repeat(64),
        );
        let error =
            supply_before_serving(Some(&store), [&drifted], StartupSource::PersistedSnapshot)
                .await
                .unwrap_err()
                .to_string();
        assert_eq!(
            error,
            "UI_DESCRIPTOR_CONFLICT: persisted snapshot site site_a policy revision policy-r1 \
             already binds other action descriptors"
        );
        // Nothing was overwritten.
        assert_eq!(
            store.revision("tenant_supply", "site_a", "policy-r1"),
            Some(("active", "e".repeat(64)))
        );
        let down = FakeStore::new(Mode::Down);
        for store in [None, Some(&down as &dyn DescriptorStore)] {
            let error = supply_before_serving(store, [&drifted], StartupSource::PersistedSnapshot)
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                "IDENTITY_STORE_UNAVAILABLE: persisted snapshot site site_a cannot supply its \
                 action descriptors"
            );
        }
    }

    // The bootstrap path keeps the messages operators and the browser loop
    // already match on.
    #[tokio::test]
    async fn the_bootstrap_configuration_keeps_its_startup_messages() {
        let config = compiled(&page_site("site_a", 6100, "/orders"));
        let digest = config.edge_descriptors().unwrap().content_digest_hex();
        let store = FakeStore::new(Mode::Up);
        store.seed("tenant_supply", "site_a", "policy-r1", "retired", &digest);
        let conflict = supply_before_serving(Some(&store), [&config], StartupSource::Bootstrap)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            conflict,
            "UI_DESCRIPTOR_CONFLICT: policy revision policy-r1 already binds other action \
             descriptors"
        );
        let down = FakeStore::new(Mode::Down);
        let unavailable = supply_before_serving(Some(&down), [&config], StartupSource::Bootstrap)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(unavailable, "IDENTITY_STORE_UNAVAILABLE");
        // Without page issuance there is nothing to supply and no store is
        // needed, which is every bootstrap-only placeholder configuration.
        assert_eq!(
            supply_before_serving(None, [&plain_site()], StartupSource::Bootstrap)
                .await
                .unwrap(),
            []
        );
    }

    #[tokio::test]
    async fn every_store_answer_maps_to_one_refusal() {
        let config = compiled(&page_site("site_a", 6100, "/orders"));
        let conflict = SupplyRefusal::Conflict {
            site_id: config.site_id().clone(),
            policy_revision: config.policy_revision().clone(),
        };
        let unavailable = SupplyRefusal::Unavailable {
            site_id: config.site_id().clone(),
        };
        // A descriptor row that means something else.
        let drifted = FakeStore::new(Mode::Up);
        drifted.drift_descriptor("tenant_supply", "site_a", "policy-r1");
        assert_eq!(
            supply_descriptors(Some(&drifted), [&config], APPLY_SUPPLY_DEADLINE).await,
            Err(conflict.clone())
        );
        // A set outside the store's own bounds is a conflict, not an outage.
        assert_eq!(
            supply_descriptors(Some(&Oversized), [&config], APPLY_SUPPLY_DEADLINE).await,
            Err(conflict)
        );
        // A database that never answers is cut off by the deadline.
        let hung = FakeStore::new(Mode::Hung);
        let started = std::time::Instant::now();
        assert_eq!(
            supply_descriptors(Some(&hung), [&config], Duration::from_millis(50)).await,
            Err(unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A database that answers, slowly.
    struct SlowStore;

    #[async_trait]
    impl DescriptorStore for SlowStore {
        async fn sync(
            &self,
            _: &GatewayConfig,
            _: &EdgeDescriptorSet,
        ) -> Result<EdgeDescriptorSyncOutcome, StoreError> {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(EdgeDescriptorSyncOutcome::Created)
        }
    }

    // The deadline covers the whole snapshot, not each site: a second site
    // gets only what the first one left of it.
    #[tokio::test]
    async fn the_deadline_bounds_the_whole_snapshot() {
        let first = compiled(&page_site("site_a", 6100, "/orders"));
        let second = compiled(&page_site("site_b", 6101, "/orders"));
        let refusal = supply_descriptors(
            Some(&SlowStore),
            [&first, &second],
            Duration::from_millis(150),
        )
        .await
        .unwrap_err();
        assert_eq!(
            refusal,
            SupplyRefusal::Unavailable {
                site_id: second.site_id().clone()
            }
        );
    }
}

/// In-memory stand-in for the descriptor rows, with the store's semantics:
/// a revision is created `active` when absent, then must be `active` and
/// carry the same digest; nothing is ever updated.
#[cfg(test)]
pub(crate) mod fake {
    use super::{DescriptorStore, async_trait};
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Mutex,
    };
    use xshield_gateway::{GatewayConfig, page_actions::EdgeDescriptorSet};
    use xshield_postgres::{EdgeDescriptorSyncOutcome, StoreError};

    /// A page-issuing site of tenant `tenant_supply`; `list_path` moves the
    /// page-issued action, which changes the descriptor set under the same
    /// policy revision.
    pub(crate) fn page_site(site: &str, port: u16, list_path: &str) -> Value {
        json!({
            "listen": format!("127.0.0.1:{port}"),
            "origin": {"address": "127.0.0.1:8080", "server_name": "origin.local", "tls": false},
            "tenant_id": "tenant_supply", "site_id": site, "policy_revision": "policy-r1",
            "audit": {"directory": format!("target/audit-{site}"), "key_id": "key-r1",
                      "producer_id": "edge-r1", "max_bytes": 16_777_216,
                      "high_watermark_bytes": 12_582_912, "segment_max_bytes": 4_194_304},
            "identity_store": {"max_connections": 2, "acquire_timeout_ms": 1000},
            "sensor": {"origin": "https://site.example", "build_ref": "a".repeat(64),
                       "heartbeat_seconds": 15},
            "operations": [
                {"operation_id": "app.page", "method": "GET", "path": "/app",
                 "admission": "AUTHENTICATED_ROOT",
                 "response": {"mode": "SENSOR_HTML", "max_bytes": 4096,
                              "adapter_revision": "app-r1", "origin_sha256": "c".repeat(64),
                              "injection_offset": 10,
                              "page_actions": {"mapping_revision": "mapping-r1",
                                               "max_active_pages": 4}}},
                {"operation_id": "orders.list", "method": "GET", "path": list_path,
                 "admission": "UI_ACTION_REQUIRED", "source_action": "app.orders.list",
                 "issued_by": {"page_operation_id": "app.page", "ttl_seconds": 60}}
            ]
        })
    }

    /// How the fake database behaves.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Mode {
        /// Answers like the real store.
        Up,
        /// Every call fails as an unreachable database would.
        Down,
        /// Every call waits forever, like a database that accepts the
        /// connection and never answers.
        Hung,
    }

    type Key = (String, String, String);

    pub(crate) struct FakeStore {
        mode: Mode,
        revisions: Mutex<BTreeMap<Key, (&'static str, String)>>,
        drifted: Mutex<BTreeSet<Key>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeStore {
        pub(crate) fn new(mode: Mode) -> Self {
            Self {
                mode,
                revisions: Mutex::new(BTreeMap::new()),
                drifted: Mutex::new(BTreeSet::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn key(tenant: &str, site: &str, revision: &str) -> Key {
            (tenant.to_owned(), site.to_owned(), revision.to_owned())
        }

        /// Stores a revision row as another edge or an operator left it.
        pub(crate) fn seed(
            &self,
            tenant: &str,
            site: &str,
            revision: &str,
            status: &'static str,
            digest: &str,
        ) {
            self.revisions.lock().unwrap().insert(
                Self::key(tenant, site, revision),
                (status, digest.to_owned()),
            );
        }

        /// Makes one stored descriptor of the revision mean something else.
        pub(crate) fn drift_descriptor(&self, tenant: &str, site: &str, revision: &str) {
            self.drifted
                .lock()
                .unwrap()
                .insert(Self::key(tenant, site, revision));
        }

        /// `site@revision#digest` for every call, in order.
        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        /// The stored `(status, digest)` of one revision.
        pub(crate) fn revision(
            &self,
            tenant: &str,
            site: &str,
            revision: &str,
        ) -> Option<(&'static str, String)> {
            self.revisions
                .lock()
                .unwrap()
                .get(&Self::key(tenant, site, revision))
                .cloned()
        }
    }

    #[async_trait]
    impl DescriptorStore for FakeStore {
        async fn sync(
            &self,
            config: &GatewayConfig,
            descriptors: &EdgeDescriptorSet,
        ) -> Result<EdgeDescriptorSyncOutcome, StoreError> {
            let digest = descriptors.content_digest_hex();
            self.calls.lock().unwrap().push(format!(
                "{}@{}#{digest}",
                config.site_id().as_str(),
                config.policy_revision().as_str()
            ));
            match self.mode {
                Mode::Up => {}
                Mode::Down => return Err(StoreError::Database(sqlx::Error::PoolTimedOut)),
                Mode::Hung => std::future::pending::<()>().await,
            }
            let key = Self::key(
                config.tenant_id().as_str(),
                config.site_id().as_str(),
                config.policy_revision().as_str(),
            );
            let mut revisions = self.revisions.lock().unwrap();
            let created = !revisions.contains_key(&key);
            let (status, stored) = revisions
                .entry(key.clone())
                .or_insert(("active", digest.clone()));
            if *status != "active" || *stored != digest {
                return Ok(EdgeDescriptorSyncOutcome::PolicyConflict);
            }
            if self.drifted.lock().unwrap().contains(&key) {
                return Ok(EdgeDescriptorSyncOutcome::DescriptorConflict);
            }
            Ok(if created {
                EdgeDescriptorSyncOutcome::Created
            } else {
                EdgeDescriptorSyncOutcome::Existing
            })
        }
    }
}
