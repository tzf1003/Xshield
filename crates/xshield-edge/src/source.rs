//! Where sites come from: the control plane's `site_configs` table, or a JSON
//! file for development and tests.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgPool, Row};
use xshield_core::context::SiteSpec;

use crate::sites::{EdgeSite, SiteTable};

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
    last_file: Option<String>,
}

impl SiteLoader {
    /// A loader that has not read anything yet.
    #[must_use]
    pub fn new(source: SiteSource, table: Arc<SiteTable>) -> Self {
        Self {
            source,
            table,
            known: HashMap::new(),
            last_file: None,
        }
    }

    /// Reads the source once and replaces the table if anything changed.
    ///
    /// A site that fails validation keeps its previous version, so a bad edit
    /// never takes a site offline.
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
        let mut next: HashMap<String, (i64, Arc<EdgeSite>)> = HashMap::new();
        let mut changed = rows.len() != self.known.len();
        for (name, version, value) in rows {
            if let Some((known_version, site)) = self.known.get(&name)
                && *known_version == version
            {
                next.insert(name, (version, Arc::clone(site)));
                continue;
            }
            match build(&value) {
                Ok(site) => {
                    changed = true;
                    next.insert(name, (version, Arc::new(site)));
                }
                Err(error) => {
                    eprintln!("xshield-edge: site {name} not loaded: {error}");
                    if let Some(previous) = self.known.get(&name) {
                        next.insert(name, previous.clone());
                    }
                }
            }
        }
        if changed {
            let mut ordered: Vec<_> = next.iter().collect();
            ordered.sort_by(|a, b| a.0.cmp(b.0));
            let sites = ordered
                .iter()
                .map(|(_, (_, site))| Arc::clone(site))
                .collect();
            for loser in self.table.replace(sites) {
                eprintln!("xshield-edge: site {loser} shares a host with an earlier site");
            }
        }
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

fn build(value: &serde_json::Value) -> Result<EdgeSite, String> {
    let spec: SiteSpec = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    EdgeSite::new(spec).map_err(|e| e.to_string())
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

        std::fs::write(
            &path,
            format!("[{},{}]", spec("a", "a.test"), spec("b", "b.test")),
        )
        .expect("write");
        loader.refresh().await.expect("second");
        assert!(table.find("b.test").is_some());

        // An invalid origin for "a" must not take it offline.
        let bad = spec("a", "a.test").replace("http://127.0.0.1:9", "ftp://x");
        std::fs::write(&path, format!("[{bad},{}]", spec("b", "b.test"))).expect("write");
        loader.refresh().await.expect("third");
        assert!(table.find("a.test").is_some());

        // A removed site disappears.
        std::fs::write(&path, format!("[{}]", spec("b", "b.test"))).expect("write");
        loader.refresh().await.expect("fourth");
        assert!(table.find("a.test").is_none());
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
