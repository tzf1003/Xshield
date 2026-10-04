//! Pure multi-site edge snapshot and routing primitives.
//!
//! The network supervisor owns sockets; this module owns the immutable route
//! decision. A request must match its internal listener and configured Host
//! before the selected site snapshot is exposed to the request pipeline.

use crate::{ConfigError, GatewayConfig};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};
use url::Url;
use uuid::Uuid;
use xshield_core::{
    GatewayApplyRequest,
    domain::{SiteId, TenantId},
};

/// One validated site entry in an edge snapshot.
pub struct GatewaySite {
    config: GatewayConfig,
    hosts: BTreeSet<String>,
}

impl GatewaySite {
    /// Creates a site route from a compiled gateway configuration and exact
    /// public host names.
    ///
    /// # Errors
    /// Returns [`ConfigError`] for an empty or malformed host set.
    pub fn new(
        config: GatewayConfig,
        hosts: impl IntoIterator<Item = String>,
    ) -> Result<Self, ConfigError> {
        let hosts = hosts
            .into_iter()
            .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if hosts.is_empty() || hosts.iter().any(|host| !valid_host(host)) {
            return Err(ConfigError::Invalid("site host"));
        }
        Ok(Self { config, hosts })
    }

    /// Returns the compiled site identity.
    #[must_use]
    pub fn site_id(&self) -> &SiteId {
        self.config.site_id()
    }
}

/// Immutable all-sites snapshot used for one request generation.
pub struct GatewaySnapshot {
    revision: u64,
    payload_digest: Option<[u8; 32]>,
    tenant_id: TenantId,
    routes: SiteRouteTable,
    sites: BTreeMap<SiteId, GatewayConfig>,
}

impl GatewaySnapshot {
    /// Compiles and validates a complete site snapshot.
    ///
    /// # Errors
    /// Returns [`ConfigError`] for duplicate sites, listeners, hosts, or
    /// mismatched tenant scopes.
    pub fn compile(revision: u64, sites: Vec<GatewaySite>) -> Result<Self, ConfigError> {
        if revision == 0 || sites.is_empty() {
            return Err(ConfigError::Invalid("snapshot"));
        }
        let tenant_id = sites[0].config.tenant_id().clone();
        Self::compile_for_tenant(revision, tenant_id, sites)
    }

    /// Compiles a snapshot for a tenant even when every site is paused or
    /// removed. An empty route set is fail-closed for all incoming requests.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when a site has a duplicate listener, host, or
    /// tenant scope.
    pub fn compile_for_tenant(
        revision: u64,
        tenant_id: TenantId,
        sites: Vec<GatewaySite>,
    ) -> Result<Self, ConfigError> {
        Self::compile_for_tenant_with_digest(revision, tenant_id, sites, None)
    }

    fn compile_for_tenant_with_digest(
        revision: u64,
        tenant_id: TenantId,
        sites: Vec<GatewaySite>,
        payload_digest: Option<[u8; 32]>,
    ) -> Result<Self, ConfigError> {
        // The caller receives a rejected snapshot and the current pointer is
        // left untouched when any site fails compilation.
        if revision == 0 {
            return Err(ConfigError::Invalid("snapshot"));
        }
        let mut routes = SiteRouteTable::default();
        let mut compiled = BTreeMap::new();
        for site in sites {
            if site.config.tenant_id() != &tenant_id || compiled.contains_key(site.config.site_id())
            {
                return Err(ConfigError::Invalid("snapshot site"));
            }
            routes.insert(&site.config, &site.hosts)?;
            compiled.insert(site.config.site_id().clone(), site.config);
        }
        Ok(Self {
            revision,
            payload_digest,
            tenant_id,
            routes,
            sites: compiled,
        })
    }

    /// Returns the immutable revision bound to new requests.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the canonical apply payload digest when this snapshot came
    /// from the authenticated apply channel.
    #[must_use]
    pub const fn payload_digest(&self) -> Option<[u8; 32]> {
        self.payload_digest
    }

    /// Returns the tenant shared by this edge snapshot.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the number of sites in this immutable snapshot.
    #[must_use]
    pub fn site_count(&self) -> usize {
        self.sites.len()
    }

    /// Returns every internal port required by this complete snapshot.
    #[must_use]
    pub fn listener_ports(&self) -> BTreeSet<u16> {
        self.sites
            .values()
            .map(|config| config.listen().port())
            .collect()
    }

    /// Resolves a request using listener port and exact configured Host/SNI.
    #[must_use]
    pub fn route(&self, listen_port: u16, host: &str) -> Option<&GatewayConfig> {
        self.routes
            .resolve(listen_port, host)
            .and_then(|site| self.sites.get(site))
    }

    /// Returns whether every configured site has a socket that the edge
    /// supervisor bound before accepting traffic.
    #[must_use]
    pub fn uses_only_listeners(&self, listeners: &BTreeSet<u16>) -> bool {
        self.sites
            .values()
            .all(|config| listeners.contains(&config.listen().port()))
    }

    /// Compiles a complete signed-envelope payload before any pointer is
    /// replaced. The caller verifies transport authentication first.
    ///
    /// # Errors
    /// Returns [`ConfigError`] for malformed protocol fields or any invalid
    /// site configuration.
    pub fn from_apply_request(request: GatewayApplyRequest) -> Result<Self, ConfigError> {
        if request.protocol_version != 1
            || request.snapshot_revision == 0
            || request
                .apply_id
                .strip_prefix("apply_")
                .and_then(|value| Uuid::parse_str(value).ok())
                .is_none_or(|value| value.get_version_num() != 7)
        {
            return Err(ConfigError::Invalid("apply request"));
        }
        let payload =
            serde_json::to_vec(&request).map_err(|_| ConfigError::Invalid("apply request"))?;
        let tenant_wire = request.tenant_id.clone();
        let tenant_id = TenantId::parse(request.tenant_id).map_err(ConfigError::Domain)?;
        let mut sites = Vec::with_capacity(request.sites.len());
        for entry in request.sites {
            let config_bytes = serde_json::to_vec(&entry.gateway_config)
                .map_err(|_| ConfigError::Invalid("apply config"))?;
            let config = GatewayConfig::from_json(&config_bytes)?;
            if config.site_id().as_str() != entry.site_id
                || config.listen().port() != entry.listen_port
                || config.tenant_id().as_str() != tenant_wire
                || entry.revision == 0
            {
                return Err(ConfigError::Invalid("apply site scope"));
            }
            let public_origin = Url::parse(&entry.public_origin)
                .map_err(|_| ConfigError::Invalid("public origin"))?;
            let loopback_origin = public_origin.host().is_some_and(|host| match host {
                url::Host::Domain(name) => name == "localhost",
                url::Host::Ipv4(ip) => ip.is_loopback(),
                url::Host::Ipv6(ip) => ip.is_loopback(),
            });
            if public_origin.host().is_none()
                || !public_origin.username().is_empty()
                || public_origin.password().is_some()
                || (public_origin.scheme() != "https" && !loopback_origin)
                || !matches!(public_origin.path(), "" | "/")
                || public_origin.query().is_some()
                || public_origin.fragment().is_some()
            {
                return Err(ConfigError::Invalid("public origin"));
            }
            let host = public_origin
                .host_str()
                .ok_or(ConfigError::Invalid("public origin host"))?
                .to_owned();
            sites.push(GatewaySite::new(config, [host])?);
        }
        Self::compile_for_tenant_with_digest(
            request.snapshot_revision,
            tenant_id,
            sites,
            Some(openssl::sha::sha256(&payload)),
        )
    }
}

/// Port and Host/SNI route table compiled with a snapshot.
#[derive(Default)]
pub struct SiteRouteTable {
    by_listener: BTreeMap<u16, SiteId>,
    by_host: BTreeMap<(u16, String), SiteId>,
}

impl SiteRouteTable {
    fn insert(
        &mut self,
        config: &GatewayConfig,
        hosts: &BTreeSet<String>,
    ) -> Result<(), ConfigError> {
        let port = config.listen().port();
        if self
            .by_listener
            .insert(port, config.site_id().clone())
            .is_some()
        {
            return Err(ConfigError::Invalid("snapshot listener"));
        }
        for host in hosts {
            if self
                .by_host
                .insert((port, host.clone()), config.site_id().clone())
                .is_some()
            {
                return Err(ConfigError::Invalid("snapshot host"));
            }
        }
        Ok(())
    }

    fn resolve(&self, port: u16, host: &str) -> Option<&SiteId> {
        let host = normalize_host(host)?;
        self.by_host.get(&(port, host))
    }
}

fn normalize_host(value: &str) -> Option<String> {
    let value = value.trim();
    let host = if let Some(value) = value.strip_prefix('[') {
        let (host, port) = value.split_once(']')?;
        if let Some(port) = port.strip_prefix(':') {
            port.parse::<u16>().ok()?;
        } else if !port.is_empty() {
            return None;
        }
        host
    } else if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        port.parse::<u16>().ok()?;
        host
    } else {
        value
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    valid_host(&host).then_some(host)
}

/// In-memory internal port lease table for an edge supervisor.
#[derive(Default)]
pub struct ListenerManager {
    leases: BTreeMap<SiteId, u16>,
}

impl ListenerManager {
    /// Reserves a private listener port for one site.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the requested port is outside the pool or
    /// already leased.
    pub fn reserve(&mut self, site_id: SiteId, requested: Option<u16>) -> Result<u16, ConfigError> {
        if let Some(current) = self.leases.get(&site_id)
            && (requested.is_none() || requested == Some(*current))
        {
            return Ok(*current);
        }
        let port = requested.unwrap_or_else(|| {
            (6100..=65535)
                .find(|candidate| !self.leases.values().any(|current| current == candidate))
                .unwrap_or(0)
        });
        if !(6100..=65535).contains(&port) || self.leases.values().any(|current| *current == port) {
            return Err(ConfigError::Invalid("listener lease"));
        }
        self.leases.insert(site_id, port);
        Ok(port)
    }

    /// Releases a site's listener lease.
    pub fn release(&mut self, site_id: &SiteId) -> bool {
        self.leases.remove(site_id).is_some()
    }
}

/// Atomic immutable snapshot holder.
pub struct ConfigSnapshotStore {
    current: RwLock<Arc<GatewaySnapshot>>,
}

impl ConfigSnapshotStore {
    /// Creates a store with the first validated snapshot.
    #[must_use]
    pub fn new(snapshot: GatewaySnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }

    /// Clones the snapshot pointer for one request.
    #[must_use]
    pub fn load(&self) -> Arc<GatewaySnapshot> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replaces the pointer only when the incoming snapshot is at least as
    /// new as the one currently serving requests. The comparison and pointer
    /// swap share one write lock so concurrent apply requests cannot make a
    /// newer snapshot regress to an older revision.
    pub fn replace_if_current_or_newer(&self, snapshot: GatewaySnapshot) -> Option<u64> {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if snapshot.revision() < current.revision()
            || (snapshot.revision() == current.revision()
                && current.payload_digest() != snapshot.payload_digest())
        {
            return None;
        }
        *current = Arc::new(snapshot);
        Some(current.revision())
    }
}

/// Validates before replacing the edge snapshot.
pub struct ApplyCoordinator {
    store: Arc<ConfigSnapshotStore>,
    listeners: Option<BTreeSet<u16>>,
}

impl ApplyCoordinator {
    /// Creates an atomic apply coordinator.
    #[must_use]
    pub fn new(store: Arc<ConfigSnapshotStore>) -> Self {
        Self {
            store,
            listeners: None,
        }
    }

    /// Creates an apply coordinator bound to the sockets already owned by the
    /// edge supervisor. New ports must be prebound until a live listener
    /// supervisor is available.
    #[must_use]
    pub fn with_listeners(store: Arc<ConfigSnapshotStore>, listeners: BTreeSet<u16>) -> Self {
        Self {
            store,
            listeners: Some(listeners),
        }
    }

    /// Returns whether an applied snapshot can be served by the bound sockets.
    #[must_use]
    pub fn accepts_listeners(&self, snapshot: &GatewaySnapshot) -> bool {
        self.listeners
            .as_ref()
            .is_none_or(|listeners| snapshot.uses_only_listeners(listeners))
    }

    /// Applies a fully compiled snapshot and returns its active revision.
    #[must_use]
    pub fn apply(&self, snapshot: GatewaySnapshot) -> u64 {
        self.apply_if_current_or_newer(snapshot)
            .unwrap_or_else(|| self.current().revision())
    }

    /// Atomically applies a snapshot unless a newer revision is already
    /// active. Compilation and listener checks happen before this method; the
    /// final revision guard is kept beside the pointer swap for concurrency.
    #[must_use]
    pub fn apply_if_current_or_newer(&self, snapshot: GatewaySnapshot) -> Option<u64> {
        if !self.accepts_listeners(&snapshot) {
            return None;
        }
        self.store.replace_if_current_or_newer(snapshot)
    }

    /// Reads the current immutable snapshot.
    #[must_use]
    pub fn current(&self) -> Arc<GatewaySnapshot> {
        self.store.load()
    }

    /// Returns the shared atomic store used by the request pipeline.
    #[must_use]
    pub fn snapshot_store(&self) -> Arc<ConfigSnapshotStore> {
        Arc::clone(&self.store)
    }
}

fn valid_host(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(site: &str, port: u16) -> GatewayConfig {
        GatewayConfig::from_json(
            &serde_json::to_vec(&json!({
                "listen": format!("127.0.0.1:{port}"),
                "origin": { "address": "127.0.0.1:8080", "server_name": "origin.local", "tls": false },
                "tenant_id": "tenant_a", "site_id": site, "policy_revision": "policy-r1",
                "audit": { "directory": format!("target/audit-{site}"), "key_id": "key-r1", "producer_id": "edge-r1", "max_bytes": 16_777_216, "high_watermark_bytes": 12_582_912, "segment_max_bytes": 4_194_304 },
                "operations": [{ "operation_id": "entry", "method": "GET", "path": "/", "admission": "PUBLIC" }]
            }))
            .expect("valid test configuration"),
        )
        .expect("compiled test configuration")
    }

    #[test]
    fn routes_by_listener_and_host_and_rejects_cross_site_duplicates() {
        let first = GatewaySite::new(config("site_a", 6100), ["a.example.com".to_owned()]).unwrap();
        let second =
            GatewaySite::new(config("site_b", 6101), ["b.example.com".to_owned()]).unwrap();
        let snapshot = GatewaySnapshot::compile(1, vec![first, second]).unwrap();
        assert_eq!(
            snapshot.listener_ports(),
            BTreeSet::from([6100, 6101]),
            "the supervisor must bind every port before swapping this snapshot"
        );
        assert_eq!(
            snapshot
                .route(6100, "a.example.com")
                .unwrap()
                .site_id()
                .as_str(),
            "site_a"
        );
        assert!(snapshot.route(6100, "b.example.com").is_none());
        assert!(snapshot.route(6100, "a.example.com:443").is_some());
        assert!(snapshot.route(6100, "a.example.com:invalid").is_none());
        let ipv6 = GatewaySite::new(config("site_ipv6", 6102), ["::1".to_owned()]).unwrap();
        let ipv6_snapshot = GatewaySnapshot::compile(2, vec![ipv6]).unwrap();
        assert!(ipv6_snapshot.route(6102, "[::1]:6102").is_some());
        let duplicate =
            GatewaySite::new(config("site_c", 6100), ["c.example.com".to_owned()]).unwrap();
        assert!(
            GatewaySnapshot::compile(
                2,
                vec![
                    duplicate,
                    GatewaySite::new(config("site_d", 6100), ["d.example.com".to_owned()]).unwrap()
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn apply_payload_compiles_before_snapshot_replacement() {
        let gateway_config = serde_json::to_value(serde_json::json!({
            "listen": "127.0.0.1:6100",
            "origin": { "address": "127.0.0.1:8080", "server_name": "origin.local", "tls": false },
            "tenant_id": "tenant_a", "site_id": "site_a", "policy_revision": "policy-r1",
            "audit": { "directory": "target/audit-site-a", "key_id": "key-r1", "producer_id": "edge-r1", "max_bytes": 16_777_216, "high_watermark_bytes": 12_582_912, "segment_max_bytes": 4_194_304 },
            "operations": [{ "operation_id": "entry", "method": "GET", "path": "/", "admission": "PUBLIC" }]
        }))
        .unwrap();
        let request = GatewayApplyRequest {
            protocol_version: 1,
            tenant_id: "tenant_a".to_owned(),
            apply_id: "apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01".to_owned(),
            snapshot_revision: 2,
            sites: vec![xshield_core::GatewayApplySite {
                site_id: "site_a".to_owned(),
                listen_port: 6100,
                public_origin: "https://a.example.com".to_owned(),
                gateway_config,
                revision: 2,
            }],
        };
        let snapshot = GatewaySnapshot::from_apply_request(request.clone()).unwrap();
        assert_eq!(snapshot.revision(), 2);
        assert_eq!(
            snapshot
                .route(6100, "a.example.com")
                .unwrap()
                .site_id()
                .as_str(),
            "site_a"
        );
        let mut conflicting = request;
        conflicting.sites[0].revision = 3;
        let conflicting = GatewaySnapshot::from_apply_request(conflicting).unwrap();
        let store = ConfigSnapshotStore::new(snapshot);
        assert_eq!(store.replace_if_current_or_newer(conflicting), None);
    }

    #[test]
    fn apply_rejects_an_older_snapshot_after_a_newer_one_wins() {
        let store = Arc::new(ConfigSnapshotStore::new(
            GatewaySnapshot::compile(
                1,
                vec![
                    GatewaySite::new(config("site_a", 6100), ["a.example.com".to_owned()]).unwrap(),
                ],
            )
            .unwrap(),
        ));
        let coordinator = ApplyCoordinator::new(store);
        let newer = GatewaySnapshot::compile(
            3,
            vec![GatewaySite::new(config("site_a", 6100), ["a.example.com".to_owned()]).unwrap()],
        )
        .unwrap();
        let older = GatewaySnapshot::compile(
            2,
            vec![GatewaySite::new(config("site_a", 6100), ["a.example.com".to_owned()]).unwrap()],
        )
        .unwrap();
        assert_eq!(coordinator.apply_if_current_or_newer(newer), Some(3));
        assert_eq!(coordinator.apply_if_current_or_newer(older), None);
        assert_eq!(coordinator.current().revision(), 3);
    }
}
