//! `xshield-build`: stage a front-end page build for a `SENSOR_HTML` route
//! from a release pipeline (docs/29 29.38).
//!
//! `fingerprint <page>` prints what the edge matches the page by, offline.
//! `register` reads the site's stored configuration with an Agent API Key,
//! adds the build beside the ones already served (optionally retiring old
//! ones) and saves a new revision. It never approves or applies: a changed
//! build is `SENSOR_HTML_CHANGED`, which only an independent `PolicyApprover`
//! clears, so the pipeline publishes the new front end only after that.
//!
//! Exit codes: 0 staged or nothing to stage, 1 local error, 2 refused by the
//! control plane, 3 staged on top of a revision someone else stored meanwhile.

use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use xshield_core::site::SiteConfig;
use xshield_core::site::build::{self, PageBuild, Registration};

const USAGE: &str = "usage:
  xshield-build fingerprint <page.html>
  xshield-build register --control <url> --site <site_id> --operation <operation_id>
                         --revision <adapter_revision> --page <page.html>
                         [--retire <adapter_revision>]... [--dry-run]
  register reads the Agent API Key from XSHIELD_API_KEY; the key needs
  site.read and site.config.write for the site.";

/// Fields of the configuration read that are revision metadata, not config.
const VIEW_ONLY: [&str; 6] = [
    "revision",
    "config_digest",
    "updated_by",
    "created_at",
    "updated_at",
    "gateway_config",
];

#[derive(Debug)]
enum Failure {
    Local(String),
    Refused(String),
    Concurrent(Value),
}

struct Register {
    control: reqwest::Url,
    site: String,
    operation: String,
    revision: String,
    page: String,
    retire: Vec<String>,
    dry_run: bool,
}

/// What one invocation prints and returns.
#[derive(Debug)]
pub struct Outcome {
    /// Process exit code.
    pub code: u8,
    /// JSON report, empty when there is none.
    pub stdout: String,
    /// Human-readable error, empty on success.
    pub stderr: String,
}

/// Runs one invocation; `api_key` is the value of `XSHIELD_API_KEY`.
pub async fn run(args: &[String], api_key: Option<String>) -> Outcome {
    let outcome = match args.first().map(String::as_str) {
        Some("fingerprint") if args.len() == 2 => fingerprint(&args[1]),
        Some("register") => match parse_register(&args[1..]) {
            Ok(plan) => register(plan, api_key).await,
            Err(message) => Err(Failure::Local(message)),
        },
        _ => Err(Failure::Local(USAGE.to_owned())),
    };
    let (code, stdout, stderr) = match outcome {
        Ok(report) => (0, report.to_string(), String::new()),
        Err(Failure::Local(message)) => (1, String::new(), message),
        Err(Failure::Refused(message)) => (2, String::new(), message),
        Err(Failure::Concurrent(report)) => (
            3,
            report.to_string(),
            "another revision was stored between the read and this save; the staged revision \
             includes it, so review its diff before approving"
                .to_owned(),
        ),
    };
    Outcome {
        code,
        stdout,
        stderr,
    }
}

fn read_page(path: &str) -> Result<PageBuild, Failure> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| Failure::Local(format!("cannot read {path}: {error}")))?;
    if metadata.len() > build::MAX_PAGE_BYTES as u64 {
        return Err(Failure::Local(build::BuildError::PageSize.to_string()));
    }
    let page = std::fs::read(path)
        .map_err(|error| Failure::Local(format!("cannot read {path}: {error}")))?;
    build::fingerprint(&page).map_err(|error| Failure::Local(error.to_string()))
}

fn fingerprint(path: &str) -> Result<Value, Failure> {
    let page = read_page(path)?;
    Ok(json!({
        "origin_sha256": page.origin_sha256,
        "injection_offset": page.injection_offset,
        "bytes": page.bytes,
    }))
}

fn parse_register(args: &[String]) -> Result<Register, String> {
    let mut control = None;
    let mut site = None;
    let mut operation = None;
    let mut revision = None;
    let mut page = None;
    let mut retire = Vec::new();
    let mut dry_run = false;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        if flag == "--dry-run" {
            dry_run = true;
            continue;
        }
        let value = rest
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?
            .clone();
        let slot = match flag.as_str() {
            "--control" => &mut control,
            "--site" => &mut site,
            "--operation" => &mut operation,
            "--revision" => &mut revision,
            "--page" => &mut page,
            "--retire" => {
                retire.push(value);
                continue;
            }
            _ => return Err(format!("unknown argument {flag}\n{USAGE}")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("{flag} given twice"));
        }
    }
    let missing = |name: &str| format!("missing {name}\n{USAGE}");
    let control: String = control.ok_or_else(|| missing("--control"))?;
    let control = reqwest::Url::parse(&control).map_err(|_| "--control is not a URL".to_owned())?;
    let loopback = matches!(
        control.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    );
    if control.scheme() != "https" && !(control.scheme() == "http" && loopback) {
        return Err("--control must be https (http only for a loopback host)".to_owned());
    }
    let site = site.ok_or_else(|| missing("--site"))?;
    if site.is_empty()
        || site.len() > 128
        || !site
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("--site is not a site ID".to_owned());
    }
    Ok(Register {
        control,
        site,
        operation: operation.ok_or_else(|| missing("--operation"))?,
        revision: revision.ok_or_else(|| missing("--revision"))?,
        page: page.ok_or_else(|| missing("--page"))?,
        retire,
        dry_run,
    })
}

struct Control {
    http: reqwest::Client,
    base: reqwest::Url,
    key: String,
    run: String,
}

impl Control {
    fn url(&self, path: &str) -> Result<reqwest::Url, Failure> {
        self.base
            .join(path)
            .map_err(|_| Failure::Local("cannot build the control URL".to_owned()))
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Value, Failure> {
        let response = request
            .header("X-Xshield-API-Key", &self.key)
            .header("X-Xshield-Agent-Run-Id", &self.run)
            .send()
            .await
            .map_err(|error| Failure::Refused(format!("control plane unreachable: {error}")))?;
        let status = response.status();
        let body: Value = response.json().await.map_err(|_| {
            Failure::Refused(format!("control plane answered {status} without JSON"))
        })?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(Failure::Refused(format!(
                "control plane answered {status}: {}",
                body.get("error_code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
            )))
        }
    }
}

async fn register(plan: Register, api_key: Option<String>) -> Result<Value, Failure> {
    let page = read_page(&plan.page)?;
    let key = api_key
        .filter(|key| !key.is_empty())
        .ok_or_else(|| Failure::Local("XSHIELD_API_KEY is not set".to_owned()))?;
    let control = Control {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| Failure::Local(format!("cannot build the HTTP client: {error}")))?,
        base: plan.control.clone(),
        key,
        run: format!("agt_{}", uuid::Uuid::now_v7()),
    };
    let config_path = format!("control/v1/sites/{}/config", plan.site);
    let (mut config, base_revision, base_digest) = read_config(&control, &config_path).await?;
    let summary = |state: &str| {
        json!({
            "state": state,
            "site_id": plan.site,
            "operation_id": plan.operation,
            "adapter_revision": plan.revision,
            "origin_sha256": page.origin_sha256,
            "injection_offset": page.injection_offset,
            "retired": plan.retire,
            "base_revision": base_revision,
        })
    };
    match build::register(
        &mut config,
        &plan.operation,
        &plan.revision,
        &page,
        &plan.retire,
    ) {
        Ok(Registration::Unchanged) => return Ok(summary("unchanged")),
        Ok(Registration::Changed) => {}
        Err(error) => return Err(Failure::Local(error.to_string())),
    }
    config
        .validate()
        .map_err(|error| Failure::Local(format!("the new configuration is invalid: {error:?}")))?;
    if plan.dry_run {
        return Ok(summary("dry_run"));
    }
    let saved = control
        .send(
            control
                .http
                .put(control.url(&config_path)?)
                .header(
                    "Idempotency-Key",
                    idempotency_key(&plan, &page, &base_digest),
                )
                .json(&config),
        )
        .await?;
    let desired = saved.get("desired_revision").and_then(Value::as_u64);
    let mut report = summary("staged");
    for field in [
        "desired_revision",
        "active_revision",
        "apply_state",
        "requires_approval",
        "reason_code",
        "config_digest",
    ] {
        report[field] = saved.get(field).cloned().unwrap_or(Value::Null);
    }
    // Saving does not compare against the revision that was read, so check
    // afterwards that nothing was stored in between.
    let previous = match desired {
        Some(desired) => previous_revision(&control, &plan.site, desired).await?,
        None => None,
    };
    if desired.is_none() || previous != Some(base_revision) {
        return Err(Failure::Concurrent(report));
    }
    Ok(report)
}

/// The stored configuration with its revision and digest.
async fn read_config(control: &Control, path: &str) -> Result<(SiteConfig, u64, String), Failure> {
    let read = control.send(control.http.get(control.url(path)?)).await?;
    let mut stored = read
        .get("config")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| Failure::Refused("the site has no stored configuration".to_owned()))?;
    let revision = stored.get("revision").and_then(Value::as_u64);
    let digest = stored
        .get("config_digest")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let (Some(revision), Some(digest)) = (revision, digest) else {
        return Err(Failure::Refused(
            "the configuration read has no revision".to_owned(),
        ));
    };
    for key in VIEW_ONLY {
        stored.remove(key);
    }
    let config = serde_json::from_value(Value::Object(stored)).map_err(|error| {
        Failure::Local(format!(
            "the stored configuration is not one this tool understands ({error}); upgrade xshield-build"
        ))
    })?;
    Ok((config, revision, digest))
}

/// A re-run of the same step after a lost answer replays instead of storing
/// a second revision; any different input is a different key.
fn idempotency_key(plan: &Register, page: &PageBuild, base_digest: &str) -> String {
    let mut digest = Sha256::new();
    for part in [
        plan.site.as_str(),
        &plan.operation,
        &plan.revision,
        &page.origin_sha256,
        base_digest,
    ]
    .into_iter()
    .chain(plan.retire.iter().map(String::as_str))
    {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    digest
        .finalize()
        .iter()
        .take(24)
        .fold(String::from("xshield-build:"), |mut key, byte| {
            use std::fmt::Write as _;
            let _ = write!(key, "{byte:02x}");
            key
        })
}

/// The newest stored revision before `desired`.
async fn previous_revision(
    control: &Control,
    site: &str,
    desired: u64,
) -> Result<Option<u64>, Failure> {
    let revisions = control
        .send(
            control
                .http
                .get(control.url(&format!("control/v1/sites/{site}/revisions"))?),
        )
        .await?;
    Ok(revisions
        .get("revisions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("revision").and_then(Value::as_u64))
        .filter(|revision| *revision < desired)
        .max())
}
