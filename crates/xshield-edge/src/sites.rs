//! The Host to site table, and what each site's load reported (docs/07 section 7.7.3).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use http::Uri;
use serde::Serialize;
use tokio::sync::Notify;
use xshield_core::context::SiteSpec;

/// The stable code for a site whose origin is not an http(s) authority.
pub const ORIGIN_INVALID: &str = "SITE_CONFIG_ORIGIN_INVALID";

/// The stable code for a site that lost its host to an earlier site.
pub const HOST_TAKEN: &str = "SITE_HOST_TAKEN";

/// A site together with the parsed origin address and the version it was loaded at.
#[derive(Debug)]
pub struct EdgeSite {
    spec: SiteSpec,
    version: i64,
    address: (String, u16),
    tls: bool,
}

/// Why a site cannot be served.
#[derive(Debug, PartialEq, Eq)]
pub struct OriginError(pub String);

impl std::fmt::Display for OriginError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{ORIGIN_INVALID}: {}", self.0)
    }
}

impl std::error::Error for OriginError {}

impl EdgeSite {
    /// Parses `spec.origin()` (`http(s)://host[:port]`, no path) and records the
    /// configuration `version` the site was loaded at.
    ///
    /// # Errors
    /// [`OriginError`] when the origin is not an http(s) authority.
    pub fn new(spec: SiteSpec, version: i64) -> Result<Self, OriginError> {
        let fail = |why: &str| OriginError(format!("{}: {why}", spec.name()));
        let uri: Uri = spec.origin().parse().map_err(|_| fail("not a valid URL"))?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(fail("scheme must be http or https")),
        };
        if uri.path_and_query().is_some_and(|p| p.as_str() != "/") || uri.query().is_some() {
            return Err(fail("origin must not carry a path or query"));
        }
        let host = uri.host().ok_or_else(|| fail("missing host"))?.to_owned();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        Ok(Self {
            spec,
            version,
            address: (host, port),
            tls,
        })
    }

    /// The validated configuration.
    #[must_use]
    pub fn spec(&self) -> &SiteSpec {
        &self.spec
    }

    /// The configuration version this site was loaded at.
    #[must_use]
    pub fn version(&self) -> i64 {
        self.version
    }

    /// Origin host and port.
    #[must_use]
    pub fn address(&self) -> (&str, u16) {
        (&self.address.0, self.address.1)
    }

    /// Whether the origin is reached over TLS.
    #[must_use]
    pub fn tls(&self) -> bool {
        self.tls
    }
}

/// What the table reports about one site, for the heartbeat (docs/07 section 7.7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteStatus {
    /// The version the site serves, when it serves one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// Why the newest version is not in service; absent when all is well.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SiteStatus {
    /// A site serving `version` without trouble.
    #[must_use]
    pub fn serving(version: i64) -> Self {
        Self {
            version: Some(version),
            error: None,
        }
    }

    /// A site whose newest version could not be used; `version` is the one
    /// still served, when there is one.
    #[must_use]
    pub fn failed(version: Option<i64>, code: &str) -> Self {
        Self {
            version,
            error: Some(code.to_owned()),
        }
    }
}

/// Shared, atomically replaced routing table, with the status of every site.
#[derive(Default)]
pub struct SiteTable {
    routes: RwLock<Arc<HashMap<String, Arc<EdgeSite>>>>,
    statuses: RwLock<BTreeMap<String, SiteStatus>>,
    changed: Arc<Notify>,
}

impl SiteTable {
    /// An empty table: every request is unrouted until sites are loaded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole table. When two sites claim one host the first in
    /// the given order keeps it; the loser's name is returned.
    pub fn replace(&self, sites: Vec<Arc<EdgeSite>>) -> Vec<String> {
        let mut routes = HashMap::new();
        let mut conflicts = Vec::new();
        for site in sites {
            let mut lost = false;
            for host in site.spec().hosts() {
                if routes.contains_key(host) {
                    lost = true;
                } else {
                    routes.insert(host.clone(), Arc::clone(&site));
                }
            }
            if lost {
                conflicts.push(site.spec().name().to_owned());
            }
        }
        *self
            .routes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(routes);
        self.changed.notify_one();
        conflicts
    }

    /// Replaces the status of every site. Wakes the heartbeat only when a
    /// status actually differs.
    pub fn set_statuses(&self, statuses: BTreeMap<String, SiteStatus>) {
        let mut current = self
            .statuses
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current != statuses {
            *current = statuses;
            self.changed.notify_one();
        }
    }

    /// Every site's status, by site name.
    #[must_use]
    pub fn statuses(&self) -> BTreeMap<String, SiteStatus> {
        self.statuses
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Wakes a waiter when the routes or a status change.
    #[must_use]
    pub fn changed(&self) -> Arc<Notify> {
        Arc::clone(&self.changed)
    }

    /// The site for a `Host` header value (any case, optional port).
    #[must_use]
    pub fn find(&self, host: &str) -> Option<Arc<EdgeSite>> {
        let bare = host.rsplit_once(':').map_or(host, |(name, port)| {
            if port.bytes().all(|byte| byte.is_ascii_digit()) {
                name
            } else {
                host
            }
        });
        let routes = Arc::clone(
            &self
                .routes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        routes.get(&bare.to_ascii_lowercase()).cloned()
    }

    /// Number of host names served.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether no host is served.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn site(name: &str, host: &str, origin: &str) -> Result<Arc<EdgeSite>, String> {
        let json = format!(
            r#"{{"name":"{name}","hosts":["{host}"],"origin":"{origin}","session":{{"cookie":"sid"}},"entries":["/login"]}}"#
        );
        let spec = SiteSpec::from_json(&json).map_err(|e| e.to_string())?;
        EdgeSite::new(spec, 7)
            .map(Arc::new)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn origin_forms() {
        let plain = site("a", "a.test", "http://10.0.0.5:8080").expect("plain");
        assert_eq!(plain.address(), ("10.0.0.5", 8080));
        assert!(!plain.tls());
        assert_eq!(plain.version(), 7);
        let secure = site("b", "b.test", "https://origin.test").expect("secure");
        assert_eq!(secure.address(), ("origin.test", 443));
        assert!(secure.tls());
        assert!(site("c", "c.test", "ftp://x").is_err());
        assert!(site("d", "d.test", "http://x/app").is_err());
    }

    #[test]
    fn lookup_ignores_case_and_port_and_first_site_wins() {
        let table = SiteTable::new();
        assert!(table.find("a.test").is_none());
        let conflicts = table.replace(vec![
            site("one", "a.test", "http://127.0.0.1:1").expect("one"),
            site("two", "a.test", "http://127.0.0.1:2").expect("two"),
        ]);
        assert_eq!(conflicts, vec!["two".to_owned()]);
        assert_eq!(
            table.find("A.Test:8443").expect("found").spec().name(),
            "one"
        );
        assert!(table.find("other.test").is_none());
        assert_eq!(table.len(), 1);
    }

    #[tokio::test]
    async fn statuses_wake_the_waiter_only_when_they_change() {
        let table = SiteTable::new();
        let changed = table.changed();
        let mut statuses = BTreeMap::new();
        statuses.insert("a".to_owned(), SiteStatus::serving(1));
        table.set_statuses(statuses.clone());
        assert_eq!(table.statuses(), statuses);
        // The change left a permit, so the waiter wakes once.
        tokio::time::timeout(Duration::from_millis(100), changed.notified())
            .await
            .expect("woken by the change");
        // An identical set is not a change: nothing wakes the waiter.
        table.set_statuses(statuses);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), changed.notified())
                .await
                .is_err()
        );
    }

    #[test]
    fn a_status_serializes_with_only_the_fields_it_has() {
        let served = serde_json::to_value(SiteStatus::serving(12)).expect("json");
        assert_eq!(served, serde_json::json!({"version": 12}));
        let failed = serde_json::to_value(SiteStatus::failed(None, ORIGIN_INVALID)).expect("json");
        assert_eq!(
            failed,
            serde_json::json!({"error": "SITE_CONFIG_ORIGIN_INVALID"})
        );
    }
}
