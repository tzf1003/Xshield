//! Dependency-graph gate for the pure domain crate (AGENTS.md "领域层纯逻辑；只通过
//! ports访问存储/模型/秘密/网络").
//!
//! `cargo test --workspace` in CI runs this file, so a change that makes
//! `xshield-core` reach a database driver, an HTTP client/server stack, an async
//! runtime, a TLS stack or another workspace adapter crate fails the build. The
//! check reads the resolved workspace `Cargo.lock` (which Cargo refreshes before
//! compiling, so a new `[dependencies]` entry is already visible) and walks the
//! transitive closure of `xshield-core`. The lock lists normal, build and dev
//! dependencies together, so the walk is deliberately conservative.
//!
//! Source files are additionally scanned for socket I/O from `std::net`; plain
//! address value types (`IpAddr`, `SocketAddr`) stay allowed because the domain
//! validates upstream addresses without opening connections. `std::fs` is not
//! banned: `secret_env` reads mounted secret files and `resident` writes a local
//! liveness file, neither of which is a database or HTTP boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Crate-name prefixes the domain must never reach, with the boundary they cross.
const FORBIDDEN_PREFIXES: &[(&str, &str)] = &[
    ("sqlx", "database driver"),
    ("libsqlite3", "database driver"),
    ("postgres", "database driver"),
    ("tokio-postgres", "database driver"),
    ("clickhouse", "database client"),
    ("redis", "database client"),
    ("hyper", "HTTP stack"),
    ("reqwest", "HTTP client"),
    ("axum", "HTTP server"),
    ("h2", "HTTP/2 stack"),
    ("http", "HTTP types"),
    ("tower", "HTTP middleware"),
    ("pingora", "proxy runtime"),
    ("quinn", "QUIC transport"),
    ("oauth2", "HTTP identity client"),
    ("openidconnect", "HTTP identity client"),
    ("tokio", "async runtime"),
    ("mio", "socket I/O"),
    ("socket2", "socket I/O"),
    ("rustls", "TLS stack"),
    ("openssl", "TLS stack"),
    ("xshield-postgres", "storage adapter"),
    ("xshield-audit", "journal adapter"),
    ("xshield-evidence", "evidence storage adapter"),
    ("xshield-gateway", "edge adapter"),
    ("xshield-control", "control-plane adapter"),
    ("xshield-worker", "worker adapter"),
];

/// Socket I/O entry points of the standard library that bypass every port.
const FORBIDDEN_SOURCE_TOKENS: &[&str] = &[
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "UnixStream",
    "UnixListener",
    "to_socket_addrs",
];

#[derive(Debug)]
struct Package {
    name: String,
    version: String,
    dependencies: Vec<String>,
}

fn unquote(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches(',');
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
}

/// Parses the `[[package]]` tables of a version 3/4 `Cargo.lock`.
fn parse_lock(text: &str) -> Vec<Package> {
    let mut packages = Vec::new();
    let mut current: Option<Package> = None;
    let mut in_dependencies = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" || (trimmed.starts_with('[') && !in_dependencies) {
            packages.extend(current.take());
            if trimmed == "[[package]]" {
                current = Some(Package {
                    name: String::new(),
                    version: String::new(),
                    dependencies: Vec::new(),
                });
            }
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if in_dependencies {
            if trimmed == "]" {
                in_dependencies = false;
            } else if let Some(entry) = unquote(trimmed) {
                package.dependencies.push(entry);
            }
        } else if let Some(value) = trimmed.strip_prefix("name = ") {
            package.name = unquote(value).unwrap_or_default();
        } else if let Some(value) = trimmed.strip_prefix("version = ") {
            package.version = unquote(value).unwrap_or_default();
        } else if let Some(rest) = trimmed.strip_prefix("dependencies = [") {
            // Cargo writes multi-line arrays; tolerate the single-line form too.
            if let Some(inline) = rest.strip_suffix(']') {
                package
                    .dependencies
                    .extend(inline.split(',').filter_map(unquote));
            } else {
                in_dependencies = true;
            }
        }
    }
    packages.extend(current);
    packages
}

/// Returns every package reachable from `root`, as `name version`.
fn closure(packages: &[Package], root: &str) -> Result<BTreeSet<(String, String)>, String> {
    let mut by_name: BTreeMap<&str, Vec<&Package>> = BTreeMap::new();
    for package in packages {
        by_name.entry(&package.name).or_default().push(package);
    }
    let resolve = |entry: &str| -> Result<&Package, String> {
        // Entries are `name`, `name version` or `name version (source)`.
        let mut parts = entry.split_whitespace();
        let name = parts.next().unwrap_or_default();
        let version = parts.next();
        let candidates = by_name
            .get(name)
            .ok_or_else(|| format!("lock entry {entry:?} names no package"))?;
        match version {
            Some(version) => candidates
                .iter()
                .copied()
                .find(|package| package.version == version)
                .ok_or_else(|| format!("lock entry {entry:?} names no package version")),
            None if candidates.len() == 1 => Ok(candidates[0]),
            None => Err(format!("lock entry {entry:?} is ambiguous")),
        }
    };
    let mut seen = BTreeSet::new();
    let mut pending = vec![resolve(root)?];
    while let Some(package) = pending.pop() {
        if !seen.insert((package.name.clone(), package.version.clone())) {
            continue;
        }
        for entry in &package.dependencies {
            pending.push(resolve(entry)?);
        }
    }
    Ok(seen)
}

fn forbidden_reason(name: &str) -> Option<&'static str> {
    FORBIDDEN_PREFIXES
        .iter()
        .find(|(prefix, _)| {
            name == *prefix
                || name
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(['-', '_']))
        })
        .map(|(_, reason)| *reason)
}

/// Lists every forbidden package reachable from `root`.
fn violations(lock: &str, root: &str) -> Result<Vec<String>, String> {
    let packages = parse_lock(lock);
    Ok(closure(&packages, root)?
        .into_iter()
        .filter_map(|(name, version)| {
            forbidden_reason(&name).map(|reason| format!("{name} {version} ({reason})"))
        })
        .collect())
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn source_violations(text: &str) -> Vec<&'static str> {
    FORBIDDEN_SOURCE_TOKENS
        .iter()
        .copied()
        .filter(|token| {
            text.match_indices(token).any(|(index, _)| {
                let before = text[..index].chars().next_back();
                let after = text[index + token.len()..].chars().next();
                !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                    && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
        })
        .collect()
}

#[test]
fn domain_crate_dependency_closure_reaches_no_database_http_runtime_or_adapter_crate() {
    let lock = std::fs::read_to_string(crate_dir().join("../../Cargo.lock")).unwrap();
    let packages = parse_lock(&lock);
    let reached = closure(&packages, "xshield-core").unwrap();
    // The walk really happened: the declared direct dependencies are reachable.
    for direct in ["serde", "serde_json", "sha2", "subtle"] {
        assert!(
            reached.iter().any(|(name, _)| name == direct),
            "{direct} missing from the xshield-core closure"
        );
    }
    // The workspace does use these crates, so the absence below is meaningful.
    for adapter in ["sqlx", "tokio", "hyper", "reqwest", "clickhouse"] {
        assert!(
            packages.iter().any(|package| package.name == adapter),
            "{adapter} is no longer in the workspace lock; revisit this gate"
        );
    }
    assert_eq!(
        violations(&lock, "xshield-core").unwrap(),
        Vec::<String>::new(),
        "xshield-core must reach storage/network only through its ports"
    );
}

#[test]
fn domain_sources_open_no_sockets() {
    let mut sources = Vec::new();
    rust_sources(&crate_dir().join("src"), &mut sources);
    assert!(sources.len() > 10, "source walk found {sources:?}");
    let offenders: Vec<_> = sources
        .iter()
        .filter_map(|path| {
            let found = source_violations(&std::fs::read_to_string(path).unwrap());
            (!found.is_empty()).then(|| format!("{}: {found:?}", path.display()))
        })
        .collect();
    assert_eq!(offenders, Vec::<String>::new());
}

#[test]
fn dependency_gate_rejects_a_domain_crate_that_reaches_a_database_or_http_sdk() {
    let lock = r#"
version = 4

[[package]]
name = "xshield-core"
version = "0.1.0"
dependencies = [
 "serde",
 "helper",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "helper"
version = "0.2.0"
dependencies = [
 "sqlx-postgres",
 "reqwest 0.12.0",
]

[[package]]
name = "sqlx-postgres"
version = "0.8.0"

[[package]]
name = "reqwest"
version = "0.11.0"

[[package]]
name = "reqwest"
version = "0.12.0"
dependencies = ["hyper"]

[[package]]
name = "hyper"
version = "1.0.0"

[[package]]
name = "httparse-free-standing"
version = "1.0.0"
"#;
    // A violation is caught even when it is only transitive and version-qualified.
    assert_eq!(
        violations(lock, "xshield-core").unwrap(),
        [
            "hyper 1.0.0 (HTTP stack)",
            "reqwest 0.12.0 (HTTP client)",
            "sqlx-postgres 0.8.0 (database driver)",
        ]
    );
    // Unreachable packages and look-alike names are not reported.
    assert_eq!(violations(lock, "serde").unwrap(), Vec::<String>::new());
    assert_eq!(forbidden_reason("httparse-free-standing"), None);
    assert_eq!(forbidden_reason("http-body"), Some("HTTP types"));
    assert_eq!(forbidden_reason("tokio"), Some("async runtime"));
    // An unresolvable graph fails closed instead of passing silently.
    assert!(violations("[[package]]\nname = \"other\"\n", "xshield-core").is_err());
    assert!(
        violations(
            "[[package]]\nname = \"xshield-core\"\nversion = \"0.1.0\"\ndependencies = [\n \"ghost\",\n]\n",
            "xshield-core"
        )
        .is_err()
    );
}

#[test]
fn source_gate_rejects_socket_io_but_allows_address_values() {
    assert_eq!(
        source_violations("let stream = std::net::TcpStream::connect(addr)?;"),
        ["TcpStream"]
    );
    assert_eq!(
        source_violations("for a in host.to_socket_addrs()? {}"),
        ["to_socket_addrs"]
    );
    assert_eq!(
        source_violations("use std::net::{IpAddr, SocketAddr}; struct MyTcpStreamish;"),
        Vec::<&str>::new()
    );
}
