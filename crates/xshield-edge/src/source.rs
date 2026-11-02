//! Where sites come from: the control plane's `site_configs` table, or a JSON
//! file for development and tests.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgPool, Row};
use xshield_core::context::SiteSpec;

use crate::sites::{EdgeSite, HOST_TAKEN, ORIGIN_INVALID, SiteStatus, SiteTable};

/// How often the table is re-read.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// A site source.
#[derive(Clone)]
pub enum SiteSource {
    /// `SELECT name, spec, version FROM site_configs`.
    Postgres(PgPool),
    /// A JSON array of site specs, re-read when the file changes.
    File(PathBuf),
}

/// Loads sites and swaps them into a [`SiteTable`] when they change.
pub struct SiteLoader {
    source: SiteSource,
    table: Arc<SiteTable>,
    known: HashMap<String, (i64, Arc<EdgeSite>)>,
    losers: Vec<String>,
    last_file: Option<String>,
}

/// Why a site was not loaded: the stable code for its status, and the detail for stderr.
struct Rejection {
    code: String,
    detail: String,
}

impl SiteLoader {
    /// A loader that has not read anything yet.
    #[must_use]
    pub fn new(source: SiteSource, table: Arc<SiteTable>) -> Self {
        Self {
            source,
            table,
            known: HashMap::new(),
            losers: Vec::new(),
            last_file: None,
        }
    }

    /// Reads the source once, replaces the routes when a site changed, and
    /// publishes every site's status.
    ///
    /// A site that fails validation keeps its previous version, so a bad edit
    /// never takes a site offline; its status then carries both the version it
    /// still serves and the error.
    ///
    /// # Errors
    /// A message when the source cannot be read at all; the table is then left as it was.
    pub async fn refresh(&mut self) -> Result<(), String> {
        let rows = match &self.source {
            SiteSource::Postgres(pool) => read_rows(pool).await?,
            SiteSource::File(path) => match read_file(path, self.last_file.as_deref())? {
                Some((text, rows)) => {
                    self.last_file = Some(text);
                    rows
                }
                None => return Ok(()),
            },
        };
        // A version read for the first time is loaded now; one already loaded keeps the
        // time it was loaded at.
        let now = i64::try_from(crate::sink::now_millis()).unwrap_or(i64::MAX);
        let mut next: HashMap<String, (i64, Arc<EdgeSite>)> = HashMap::new();
        let mut statuses: BTreeMap<String, SiteStatus> = BTreeMap::new();
        for (name, version, value) in rows {
            if let Some((known_version, site)) = self.known.get(&name)
                && *known_version == version
            {
                statuses.insert(
                    name.clone(),
                    SiteStatus::serving(version, site.loaded_at_millis()),
                );
                next.insert(name, (version, Arc::clone(site)));
                continue;
            }
            match build(&value, version, now) {
                Ok(site) => {
                    statuses.insert(name.clone(), SiteStatus::serving(version, now));
                    next.insert(name, (version, Arc::new(site)));
                }
                Err(rejection) => {
                    eprintln!("xshield-edge: site {name} not loaded: {}", rejection.detail);
                    let previous = self.known.get(&name).cloned();
                    let served = previous.as_ref().map(|(_, site)| &**site);
                    statuses.insert(name.clone(), SiteStatus::failed(served, &rejection.code));
                    if let Some(previous) = previous {
                        next.insert(name, previous);
                    }
                }
            }
        }
        let changed = next.len() != self.known.len()
            || next.iter().any(|(name, (version, _))| {
                self.known
                    .get(name)
                    .is_none_or(|(known_version, _)| known_version != version)
            });
        if changed {
            let mut ordered: Vec<_> = next.iter().collect();
            ordered.sort_by(|a, b| a.0.cmp(b.0));
            let sites = ordered
                .iter()
                .map(|(_, (_, site))| Arc::clone(site))
                .collect();
            self.losers = self.table.replace(sites);
            for loser in &self.losers {
                eprintln!("xshield-edge: site {loser} shares a host with an earlier site");
            }
        }
        for loser in &self.losers {
            if let Some(status) = statuses.get_mut(loser)
                && status.error.is_none()
            {
                status.error = Some(HOST_TAKEN.to_owned());
            }
        }
        self.table.set_statuses(statuses);
        self.known = next;
        Ok(())
    }

    /// Refreshes forever at [`REFRESH_INTERVAL`], reporting failures on stderr.
    pub async fn run(mut self) {
        loop {
            if let Err(error) = self.refresh().await {
                eprintln!("xshield-edge: site refresh failed: {error}");
            }
            tokio::time::sleep(REFRESH_INTERVAL).await;
        }
    }
}

fn build(
    value: &serde_json::Value,
    version: i64,
    loaded_at_millis: i64,
) -> Result<EdgeSite, Rejection> {
    let spec = SiteSpec::from_value(value).map_err(|error| {
        let code = error.to_string();
        Rejection {
            detail: code.clone(),
            code,
        }
    })?;
    EdgeSite::new(spec, version, loaded_at_millis).map_err(|error| Rejection {
        code: ORIGIN_INVALID.to_owned(),
        detail: error.to_string(),
    })
}

type Rows = Vec<(String, i64, serde_json::Value)>;

async fn read_rows(pool: &PgPool) -> Result<Rows, String> {
    let rows = sqlx::query("SELECT name, spec, version FROM site_configs ORDER BY name")
        .fetch_all(pool)
        .await
        .map_err(|e| e.to_string())?;
    rows.iter()
        .map(|row| {
            let name: String = row.try_get("name").map_err(|e| e.to_string())?;
            let spec: serde_json::Value = row.try_get("spec").map_err(|e| e.to_string())?;
            let version: i64 = row.try_get("version").map_err(|e| e.to_string())?;
            Ok((name, version, spec))
        })
        .collect()
}

/// `None` when the file is byte-identical to the previous read.
fn read_file(path: &PathBuf, previous: Option<&str>) -> Result<Option<(String, Rows)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if previous == Some(text.as_str()) {
        return Ok(None);
    }
    let values: Vec<serde_json::Value> =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut rows = Vec::new();
    for value in values {
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{}: a site without a name", path.display()))?
            .to_owned();
        // The file has no version column: a spec's version is a hash of its text.
        let mut hasher = DefaultHasher::new();
        value.to_string().hash(&mut hasher);
        let version = i64::from_ne_bytes(hasher.finish().to_ne_bytes());
        rows.push((name, version, value));
    }
    Ok(Some((text, rows)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, host: &str) -> String {
        format!(
            r#"{{"name":"{name}","hosts":["{host}"],"origin":"http://127.0.0.1:9","session":{{"cookie":"sid"}},"entries":["/login"]}}"#
        )
    }

    #[tokio::test]
    async fn file_source_loads_changes_and_keeps_old_on_bad_edit() {
        let dir = std::env::temp_dir().join(format!("xshield-edge-sites-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("sites.json");
        std::fs::write(&path, format!("[{}]", spec("a", "a.test"))).expect("write");
        let table = Arc::new(SiteTable::new());
        let mut loader = SiteLoader::new(SiteSource::File(path.clone()), Arc::clone(&table));
        loader.refresh().await.expect("first");
        assert!(table.find("a.test").is_some());
        let first = table.statuses()["a"].clone();
        assert_eq!(first.error, None);

        std::fs::write(
            &path,
            format!("[{},{}]", spec("a", "a.test"), spec("b", "b.test")),
        )
        .expect("write");
        loader.refresh().await.expect("second");
        assert!(table.find("b.test").is_some());

        // An invalid origin for "a" must not take it offline; its status keeps
        // the version it serves and names the error.
        let bad = spec("a", "a.test").replace("http://127.0.0.1:9", "ftp://x");
        std::fs::write(&path, format!("[{bad},{}]", spec("b", "b.test"))).expect("write");
        loader.refresh().await.expect("third");
        assert!(table.find("a.test").is_some());
        let stale = &table.statuses()["a"];
        assert_eq!(stale.version, first.version);
        assert_eq!(stale.loaded_at_millis, first.loaded_at_millis);
        assert_eq!(stale.error.as_deref(), Some(ORIGIN_INVALID));

        // A removed site disappears.
        std::fs::write(&path, format!("[{}]", spec("b", "b.test"))).expect("write");
        loader.refresh().await.expect("fourth");
        assert!(table.find("a.test").is_none());
        assert!(!table.statuses().contains_key("a"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_site_keeps_its_load_time_until_its_version_changes() {
        let dir = std::env::temp_dir().join(format!("xshield-edge-loaded-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("sites.json");
        std::fs::write(&path, format!("[{}]", spec("a", "a.test"))).expect("write");
        let table = Arc::new(SiteTable::new());
        let mut loader = SiteLoader::new(SiteSource::File(path.clone()), Arc::clone(&table));
        loader.refresh().await.expect("first");
        let first_load = table.statuses()["a"].loaded_at_millis.expect("a load time");

        // The same version, read again later, keeps the time it was first loaded at.
        tokio::time::sleep(Duration::from_millis(5)).await;
        loader.refresh().await.expect("same");
        assert_eq!(table.statuses()["a"].loaded_at_millis, Some(first_load));

        // A new version is loaded now.
        let changed = spec("a", "a.test").replace("/login", "/signin");
        std::fs::write(&path, format!("[{changed}]")).expect("write");
        loader.refresh().await.expect("changed");
        let status = &table.statuses()["a"];
        assert!(status.loaded_at_millis.is_some_and(|at| at > first_load));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_host_taken_by_an_earlier_site_is_reported() {
        let table = Arc::new(SiteTable::new());
        let dir = std::env::temp_dir().join(format!("xshield-edge-taken-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("sites.json");
        std::fs::write(
            &path,
            format!(
                "[{},{}]",
                spec("a", "shared.test"),
                spec("b", "shared.test")
            ),
        )
        .expect("write");
        let mut loader = SiteLoader::new(SiteSource::File(path), Arc::clone(&table));
        loader.refresh().await.expect("refresh");
        let statuses = table.statuses();
        assert_eq!(statuses["a"].error, None);
        assert_eq!(statuses["b"].error.as_deref(), Some(HOST_TAKEN));
        assert!(statuses["b"].version.is_some());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn unreadable_source_keeps_the_table() {
        let table = Arc::new(SiteTable::new());
        let mut loader = SiteLoader::new(
            SiteSource::File(PathBuf::from("/nonexistent/xshield-sites.json")),
            Arc::clone(&table),
        );
        assert!(loader.refresh().await.is_err());
    }
}
