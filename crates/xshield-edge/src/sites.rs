//! The Host to site table.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use http::Uri;
use xshield_core::context::SiteSpec;

/// A site together with the parsed origin address.
#[derive(Debug)]
pub struct EdgeSite {
    spec: SiteSpec,
    address: (String, u16),
    tls: bool,
}

/// Why a site cannot be served.
#[derive(Debug, PartialEq, Eq)]
pub struct OriginError(pub String);

impl std::fmt::Display for OriginError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SITE_ORIGIN_INVALID: {}", self.0)
    }
}

impl std::error::Error for OriginError {}

impl EdgeSite {
    /// Parses `spec.origin()` (`http(s)://host[:port]`, no path).
    ///
    /// # Errors
    /// [`OriginError`] when the origin is not an http(s) authority.
    pub fn new(spec: SiteSpec) -> Result<Self, OriginError> {
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
            address: (host, port),
            tls,
        })
    }

    /// The validated configuration.
    #[must_use]
    pub fn spec(&self) -> &SiteSpec {
        &self.spec
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

/// Shared, atomically replaced routing table.
#[derive(Default)]
pub struct SiteTable {
    routes: RwLock<Arc<HashMap<String, Arc<EdgeSite>>>>,
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
        conflicts
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
    use super::*;

    fn site(name: &str, host: &str, origin: &str) -> Result<Arc<EdgeSite>, String> {
        let json = format!(
            r#"{{"name":"{name}","hosts":["{host}"],"origin":"{origin}","session":{{"cookie":"sid"}},"entries":["/login"]}}"#
        );
        let spec = SiteSpec::from_json(&json).map_err(|e| e.to_string())?;
        EdgeSite::new(spec).map(Arc::new).map_err(|e| e.to_string())
    }

    #[test]
    fn origin_forms() {
        let plain = site("a", "a.test", "http://10.0.0.5:8080").expect("plain");
        assert_eq!(plain.address(), ("10.0.0.5", 8080));
        assert!(!plain.tls());
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
}
