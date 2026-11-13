//! The model tab of the system page (docs/03 section 3.3; the design in
//! notes/agent-model-ui sections 2 and 5.1): the Jev judgement model and the
//! learning agent's model, as the console saves them.
//!
//! Keys are write-only. No response carries one: only whether one is set, its last
//! four characters and when it changed. A saved Jev configuration reaches the
//! gateways within about five seconds, and each gateway reports the version it
//! loaded in its heartbeat, which `loaded` shows. Until a key is saved in the
//! console, the gateways keep reading their environment.

use std::{
    collections::BTreeMap,
    sync::{Arc, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use serde::Serialize;
use serde_json::Value;
use xshield_core::{
    context::{
        config::{Mode, OnJevUnavailable},
        learning::day_of,
    },
    model::{
        AGENT_TIMEOUT_MS, AgentProvider, AgentSpec, ApiKey, ConfigError, JEV_TIMEOUT_MS, JevRoute,
        JevSpec,
    },
};
use xshield_judge::{
    jev::{JevClient, JevConfigError},
    probe::{self, Probe},
};
use xshield_postgres::{
    edge_status_store::{self, EdgeStatus},
    model_config_store::{
        self as store, AgentRecord, AgentSave, HistoryEntry, JevRecord, JevSave, ModelConfigError,
        ModelRows,
    },
    object_agent_store::{self as agent_calls, SiteDay, SiteDayCount},
    site_spec_store::{self, SiteRecord},
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    jev::{self, JevConfigBody, JevStatusFields, reported_config},
    params::{json_body, rfc3339},
    sites::{expected_version, note_from},
};

/// How many versions the history shows.
const HISTORY_LIMIT: i64 = 20;
/// The shortest time between two test calls of one group.
const TEST_INTERVAL: Duration = Duration::from_secs(10);

/// The two groups the tab edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    Jev,
    Agent,
}

impl Group {
    fn parse(text: &str) -> ApiResult<Self> {
        match text {
            "jev" => Ok(Self::Jev),
            "agent" => Ok(Self::Agent),
            _ => Err(ApiError::new(StatusCode::NOT_FOUND, "MODEL_GROUP_UNKNOWN")),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Jev => "jev",
            Self::Agent => "agent",
        }
    }
}

/// `GET /api/system/models`: both groups as saved, where the keys come from, what
/// each gateway loaded, and the Jev usage of the health window.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelsBody {
    pub jev: JevGroupBody,
    pub agent: AgentGroupBody,
}

/// The Jev judgement model.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JevGroupBody {
    /// Whether a key is in place: saved in the console, or in the environment of an
    /// online gateway.
    pub configured: bool,
    /// `console` while the console holds a key, `env` while the gateways read their
    /// environment, `null` while neither holds one.
    pub source: Option<&'static str>,
    /// The version of the saved settings; `0` before the first save.
    pub version: i64,
    /// When the settings were last saved.
    pub updated_at: Option<String>,
    /// The route: the saved one, or the one an online gateway reports from its
    /// environment.
    pub route: Option<String>,
    /// The saved address. `null` while the gateways read their environment.
    pub endpoint: Option<String>,
    /// The host an online gateway reports. Given while the gateways read their
    /// environment.
    pub endpoint_host: Option<String>,
    pub model: Option<String>,
    pub timeout_ms: Option<i64>,
    pub key: KeyBody,
    /// The environment variable the gateways read the key from, by name only.
    pub key_env: Option<String>,
    /// Whether an online gateway's environment holds a usable configuration.
    pub env_available: bool,
    /// Environment variables that are set but have no effect while the console's
    /// configuration is in use. Names only.
    pub env_overridden: Vec<String>,
    /// What each online gateway loaded.
    pub loaded: Vec<LoadedBody>,
    /// Who a save reaches: the sites, and the ones that refuse requests when Jev fails.
    pub impact: ImpactBody,
    /// The Jev calls of the health window (five minutes), as the Jev health counts them.
    pub usage: UsageBody,
}

/// The learning agent's model.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentGroupBody {
    /// Whether the agent has a model and a key it can use.
    pub configured: bool,
    /// `console` once something has been saved; `null` before that.
    pub source: Option<&'static str>,
    /// The version of the saved settings; `0` before the first save.
    pub version: i64,
    pub updated_at: Option<String>,
    /// `gateway` or `custom`.
    pub provider: &'static str,
    pub endpoint: String,
    pub model: Option<String>,
    pub timeout_ms: i64,
    pub share_key_with_jev: bool,
    pub key: KeyBody,
    /// The failure of each of the latest five calls, newest first; `null` for an answer.
    pub recent_failures: Vec<Option<String>>,
    /// The agent's calls today.
    pub usage: AgentUsageBody,
    /// Every site with the agent on, and every site that asked it today, in name order.
    pub sites: Vec<AgentSiteBody>,
}

/// The learning agent's calls on one day, counted in UTC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentUsageBody {
    /// Always `today`: the day the calls are counted on.
    pub window: &'static str,
    pub calls: i64,
    /// Calls that gave an accepted answer.
    pub ok: i64,
    /// Calls without one.
    pub failed: i64,
    /// The failure most of the failed calls ended with.
    pub top_failure: Option<String>,
    /// The sites that have the agent on.
    pub enabled_sites: usize,
}

/// One site's learning agent use: today's questions against its daily limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentSiteBody {
    pub site: String,
    /// Whether the site has the agent on.
    pub enabled: bool,
    /// Questions the site asked the agent today.
    pub used: i64,
    /// The questions the site may ask in a day.
    pub limit: i64,
    /// Today's questions without an accepted answer.
    pub failed: i64,
    /// When the site's latest question was asked, on any day.
    pub last_call_at: Option<String>,
    /// The days in a row, counting back from yesterday, on which the site used its whole limit: a week at most.
    pub full_days: i64,
}

/// A key's status. The key itself is never in a response.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeyBody {
    pub set: bool,
    pub last4: Option<String>,
    pub updated_at: Option<String>,
    /// The learning agent uses the Jev key.
    pub shared_with_jev: bool,
}

/// One online gateway's loaded Jev settings.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LoadedBody {
    pub edge: String,
    /// Always `true`: only the online gateways are listed.
    pub online: bool,
    /// `console` or `env`; `null` while the gateway has nothing loaded.
    pub source: Option<String>,
    /// The console version it loaded; `null` for the environment.
    pub version: Option<i64>,
    /// The code of its newest load failure, if any.
    pub error: Option<String>,
}

/// The sites a save reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpactBody {
    /// Every site: all of them judge through Jev.
    pub sites: usize,
    /// The sites in enforce mode whose requests are refused when Jev fails.
    pub fail_closed: Vec<String>,
}

/// Jev calls over the health window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsageBody {
    pub window_minutes: i64,
    pub calls: i64,
    /// Calls without a usable answer.
    pub failed: i64,
    pub p95_ms: Option<i64>,
}

/// The response of a save: the version the group now has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SavedBody {
    pub group: &'static str,
    pub version: i64,
}

/// The outcome of a test call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestBody {
    pub ok: bool,
    pub latency_ms: u64,
    /// The HTTP status the service answered, when it answered.
    pub status: Option<u16>,
    /// The stable failure code, when the call failed.
    pub failure: Option<&'static str>,
    /// The start of the service's own error text, at most 300 characters. Untrusted.
    pub detail: Option<String>,
    /// Whether the answer could be read; `null` when no answer came.
    pub answer_valid: Option<bool>,
    /// A sentence the server wrote about the answer; never the model's words.
    pub answer_reason: Option<&'static str>,
}

impl From<Probe> for TestBody {
    fn from(probe: Probe) -> Self {
        Self {
            ok: probe.ok,
            latency_ms: probe.latency_ms,
            status: probe.status,
            failure: probe.failure,
            detail: probe.detail,
            answer_valid: probe.answer_valid,
            answer_reason: probe.answer_reason,
        }
    }
}

/// One saved version in the history.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryBody {
    pub version: i64,
    pub at: Option<String>,
    /// `save`, or `revert_to_env` for the Jev group given back to the environment.
    pub change: String,
    /// The non-secret settings of that version.
    pub config: Value,
    /// The fields that changed, with their old and new values. A key shows its last four.
    pub changes: Vec<ChangeBody>,
    /// `replaced`, `cleared`, or `null` when the key was kept.
    pub key_change: Option<String>,
    pub key_last4: Option<String>,
    pub note: Option<String>,
    /// Whether the exact values had tested successfully before the save.
    pub tested: bool,
}

/// One changed field in the history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeBody {
    pub field: String,
    pub old: String,
    pub new: String,
}

impl From<&HistoryEntry> for HistoryBody {
    fn from(entry: &HistoryEntry) -> Self {
        Self {
            version: entry.version,
            at: rfc3339(entry.changed_at.timestamp_millis()),
            change: entry.change.clone(),
            config: entry.config.clone(),
            changes: entry
                .changes
                .iter()
                .map(|change| ChangeBody {
                    field: change.field.clone(),
                    old: change.from.clone(),
                    new: change.to.clone(),
                })
                .collect(),
            key_change: entry.key_change.clone(),
            key_last4: entry.key_last4.clone(),
            note: entry.note.clone(),
            tested: entry.tested,
        }
    }
}

impl From<ModelConfigError> for ApiError {
    fn from(error: ModelConfigError) -> Self {
        match error {
            ModelConfigError::Conflict { current } => {
                ApiError::new(StatusCode::CONFLICT, "VERSION_CONFLICT").at_version(current)
            }
            ModelConfigError::Database(cause) => ApiError::internal("model settings", cause),
            ModelConfigError::Stored => {
                ApiError::internal("model settings", "a stored value does not decode")
            }
            ModelConfigError::KeyUnavailable => {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "MODEL_KEY_UNAVAILABLE")
            }
            ModelConfigError::KeyUnreadable => {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "MODEL_KEY_UNREADABLE")
            }
            ModelConfigError::KeyRequired => {
                ApiError::new(StatusCode::BAD_REQUEST, "MODEL_KEY_REQUIRED").in_field("key")
            }
            ModelConfigError::KeyEndpointChanged => key_endpoint_changed(),
            ModelConfigError::NoteTooLong => {
                ApiError::new(StatusCode::BAD_REQUEST, "MODEL_NOTE_INVALID").in_field("note")
            }
            ModelConfigError::Refused(reason) => refused(reason),
        }
    }
}

/// A refused value: the stable code of the rule it broke, and the field it is in.
fn refused(reason: ConfigError) -> ApiError {
    let field = match reason {
        ConfigError::Route => "route",
        ConfigError::Provider => "provider",
        ConfigError::Endpoint => "endpoint",
        ConfigError::Model => "model",
        ConfigError::Timeout => "timeout_ms",
        ConfigError::Key => "key",
        ConfigError::Share => "share_key_with_jev",
    };
    ApiError::new(StatusCode::BAD_REQUEST, reason.code()).in_field(field)
}

/// A gateway-side refusal of the Jev client, for a test call.
fn client_refused(error: JevConfigError) -> ApiError {
    let code = match error {
        JevConfigError::Route => "JEV_CONFIG_ROUTE_INVALID",
        JevConfigError::Key => "JEV_CONFIG_KEY_INVALID",
        JevConfigError::Endpoint => "JEV_CONFIG_ENDPOINT_INVALID",
        JevConfigError::Timeout => "JEV_CONFIG_TIMEOUT_INVALID",
        JevConfigError::Model => "JEV_CONFIG_MODEL_INVALID",
    };
    ApiError::new(StatusCode::BAD_REQUEST, code)
}

/// The model settings routes, mounted behind the session gate with the rest of `/api`.
pub fn routes() -> Router<Arc<ControlState>> {
    Router::new()
        .route("/api/system/models", get(list))
        .route("/api/system/models/{group}", put(save).delete(revert))
        .route("/api/system/models/{group}/test", post(test))
        .route("/api/system/models/{group}/history", get(history))
}

/// `GET /api/system/models`.
///
/// # Errors
/// `INTERNAL` when the database cannot be read.
pub async fn list(State(state): State<Arc<ControlState>>) -> ApiResult<Json<ModelsBody>> {
    let rows = store::read(&state.pool).await?;
    Ok(Json(ModelsBody {
        jev: jev_state(&state, &rows.jev).await?,
        agent: agent_state(&state, &rows).await?,
    }))
}

/// The Jev group as it reads now: the saved record, the online gateways and the
/// health window. `GET` and `DELETE` both answer with it.
async fn jev_state(state: &ControlState, record: &JevRecord) -> ApiResult<JevGroupBody> {
    let now = chrono::Utc::now();
    let edges = edge_status_store::list(&state.pool).await?;
    let online: Vec<&EdgeStatus> = edges.iter().filter(|edge| edge.is_online(now)).collect();
    let sites = site_spec_store::list(&state.pool).await?;
    let usage = jev::health_summary(&state.pool, now.timestamp_millis())
        .await?
        .fields();
    Ok(jev_group(record, &online, &sites, &usage))
}

/// The Jev group as the page shows it: the saved settings when the console holds
/// a key, otherwise what the online gateways report from their environment.
fn jev_group(
    record: &JevRecord,
    online: &[&EdgeStatus],
    sites: &[SiteRecord],
    usage: &JevStatusFields,
) -> JevGroupBody {
    let reports: Vec<JevConfigBody> = online.iter().map(|edge| reported_config(edge)).collect();
    let env_available = reports
        .iter()
        .any(|report| report.env_available == Some(true));
    let env_key_var = reports.iter().find_map(|report| report.env_key_var.clone());
    let mut env_overridden: Vec<String> = Vec::new();
    for name in reports.iter().flat_map(|report| &report.env_overridden) {
        if !env_overridden.contains(name) {
            env_overridden.push(name.clone());
        }
    }
    let console_key = record.key_last4.is_some();
    let source = if console_key {
        Some("console")
    } else if env_available {
        Some("env")
    } else {
        None
    };
    let first = reports.first();
    let (route, endpoint, endpoint_host, model, timeout_ms) = if console_key {
        let spec = &record.spec;
        (
            Some(spec.route().as_str().to_owned()),
            Some(spec.endpoint().to_owned()),
            None,
            Some(spec.model().to_owned()),
            Some(i64::from(spec.timeout_ms())),
        )
    } else {
        (
            first.and_then(|report| report.route.clone()),
            None,
            first.and_then(|report| report.endpoint_host.clone()),
            first.and_then(|report| report.model.clone()),
            first.and_then(|report| report.default_timeout_ms),
        )
    };
    let loaded = online
        .iter()
        .zip(&reports)
        .map(|(edge, report)| LoadedBody {
            edge: edge.edge.clone(),
            online: true,
            source: report.config_source.clone(),
            version: report.config_version,
            error: report.config_error.clone(),
        })
        .collect();
    let fail_closed = sites
        .iter()
        .filter(|site| {
            matches!(site.spec.mode(), Mode::Enforce)
                && matches!(site.spec.on_jev_unavailable(), OnJevUnavailable::Deny)
        })
        .map(|site| site.spec.name().to_owned())
        .collect();
    JevGroupBody {
        configured: source.is_some(),
        source,
        version: record.version,
        updated_at: record
            .saved_at
            .and_then(|at| rfc3339(at.timestamp_millis())),
        route,
        endpoint,
        endpoint_host,
        model,
        timeout_ms,
        key: KeyBody {
            set: console_key || env_available,
            last4: record.key_last4.clone(),
            updated_at: record.key_at.and_then(|at| rfc3339(at.timestamp_millis())),
            shared_with_jev: false,
        },
        key_env: env_key_var,
        env_available,
        env_overridden,
        loaded,
        impact: ImpactBody {
            sites: sites.len(),
            fail_closed,
        },
        usage: UsageBody {
            window_minutes: usage.window_minutes,
            calls: usage.calls,
            failed: usage.calls - usage.ok,
            p95_ms: usage.p95_ms,
        },
    }
}

/// The learning agent group. Its key is the Jev key when the agent shares it.
fn agent_group(
    rows: &ModelRows,
    recent_failures: Vec<Option<String>>,
    usage: AgentUsageBody,
    sites: Vec<AgentSiteBody>,
) -> AgentGroupBody {
    let record: &AgentRecord = &rows.agent;
    let spec = &record.spec;
    let shared = spec.share_key_with_jev();
    let jev_gateway = matches!(rows.jev.spec.route(), JevRoute::Gateway);
    let key_set = if shared {
        rows.jev.key_last4.is_some()
    } else {
        record.key_last4.is_some()
    };
    let (last4, key_at) = if shared {
        (rows.jev.key_last4.clone(), rows.jev.key_at)
    } else {
        (record.key_last4.clone(), record.key_at)
    };
    AgentGroupBody {
        configured: spec.model().is_some() && key_set && (!shared || jev_gateway),
        source: (record.version > 0).then_some("console"),
        version: record.version,
        updated_at: record
            .saved_at
            .and_then(|at| rfc3339(at.timestamp_millis())),
        provider: spec.provider().as_str(),
        endpoint: spec.endpoint().to_owned(),
        model: spec.model().map(str::to_owned),
        timeout_ms: i64::from(spec.timeout_ms()),
        share_key_with_jev: shared,
        key: KeyBody {
            set: key_set,
            last4,
            updated_at: key_at.and_then(|at| rfc3339(at.timestamp_millis())),
            shared_with_jev: shared,
        },
        recent_failures,
        usage,
        sites,
    }
}

/// The calls the agent's health reads: the latest five.
const RECENT_CALLS: i64 = 5;

/// The learning agent group as it reads now: the saved record, the failures of the latest
/// calls, today's calls and each site's share of them.
async fn agent_state(state: &ControlState, rows: &ModelRows) -> ApiResult<AgentGroupBody> {
    let pool = &state.pool;
    let now = chrono::Utc::now().timestamp_millis();
    let day = day_of(u64::try_from(now).unwrap_or(0));
    let totals = agent_calls::day_usage(pool, day).await?;
    let per_site = agent_calls::day_usage_by_site(pool, day).await?;
    let history = agent_calls::calls_by_site_and_day(
        pool,
        day.saturating_sub(FULL_DAYS_LOOKBACK),
        day.saturating_sub(1),
    )
    .await?;
    let sites = site_spec_store::list(pool).await?;
    let recent = agent_calls::recent_outcomes(pool, RECENT_CALLS).await?;
    let usage = AgentUsageBody {
        window: "today",
        calls: totals.calls,
        ok: totals.calls - totals.failed,
        failed: totals.failed,
        top_failure: totals.top_failure,
        enabled_sites: sites.iter().filter(|site| agent_on(site)).count(),
    };
    Ok(agent_group(
        rows,
        recent,
        usage,
        agent_sites(&sites, &per_site, &history, day),
    ))
}

/// Whether a site has the learning agent on.
fn agent_on(site: &SiteRecord) -> bool {
    site.spec.objects().learning().agent.enabled
}

/// The days before today that a site's run of full days can count: a week.
const FULL_DAYS_LOOKBACK: u64 = 7;

/// The sites with the agent on, and the sites that asked it today, in name order, with their
/// share of today's questions and their run of full days.
fn agent_sites(
    sites: &[SiteRecord],
    per_site: &[SiteDay],
    history: &[SiteDayCount],
    today: u64,
) -> Vec<AgentSiteBody> {
    sites
        .iter()
        .filter_map(|record| {
            let name = record.spec.name();
            let enabled = agent_on(record);
            let limit = i64::from(record.spec.objects().learning().agent.daily_limit);
            let current = per_site.iter().find(|row| row.site == name);
            let used = current.map_or(0, |row| row.used);
            if !enabled && used == 0 {
                return None;
            }
            Some(AgentSiteBody {
                site: name.to_owned(),
                enabled,
                used,
                limit,
                failed: current.map_or(0, |row| row.failed),
                last_call_at: current
                    .and_then(|row| row.last_call_millis)
                    .and_then(rfc3339),
                full_days: full_days(name, limit, history, today),
            })
        })
        .collect()
}

/// The run of full days a site has: counting back from yesterday, the days on which it asked as
/// many questions as its limit, at most [`FULL_DAYS_LOOKBACK`]. A site without a limit has none.
fn full_days(site: &str, limit: i64, history: &[SiteDayCount], today: u64) -> i64 {
    if limit <= 0 {
        return 0;
    }
    let mut run = 0;
    for back in 1..=FULL_DAYS_LOOKBACK {
        let Some(day) = today.checked_sub(back) else {
            break;
        };
        let used = history
            .iter()
            .find(|row| row.site == site && row.day == day)
            .map_or(0, |row| row.used);
        if used < limit {
            break;
        }
        run += 1;
    }
    run
}

/// The Jev values of a request body: route, endpoint, model and timeout.
fn jev_spec(body: &Value) -> ApiResult<JevSpec> {
    let route_text = text_of(body, "route")?.ok_or_else(|| ApiError::invalid_body("route"))?;
    let route = JevRoute::parse(&route_text).ok_or_else(|| refused(ConfigError::Route))?;
    let endpoint = text_of(body, "endpoint")?;
    let model = text_of(body, "model")?;
    let timeout = timeout_of(body, JEV_TIMEOUT_MS)?;
    JevSpec::new(route, endpoint.as_deref(), model.as_deref(), timeout).map_err(refused)
}

/// The agent values of a request body: provider, endpoint, model, timeout and the
/// key-sharing choice.
fn agent_spec(body: &Value) -> ApiResult<AgentSpec> {
    let provider_text =
        text_of(body, "provider")?.ok_or_else(|| ApiError::invalid_body("provider"))?;
    let provider =
        AgentProvider::parse(&provider_text).ok_or_else(|| refused(ConfigError::Provider))?;
    let endpoint = text_of(body, "endpoint")?;
    let model = text_of(body, "model")?;
    let timeout = timeout_of(body, AGENT_TIMEOUT_MS)?;
    let share = match body.get("share_key_with_jev") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err(ApiError::invalid_body("share_key_with_jev")),
    };
    AgentSpec::new(
        provider,
        endpoint.as_deref(),
        model.as_deref(),
        timeout,
        share,
    )
    .map_err(refused)
}

/// A text field: absent or null is `None`; anything but text is refused.
fn text_of(body: &Value, field: &str) -> ApiResult<Option<String>> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(ApiError::invalid_body(field)),
    }
}

/// The timeout in milliseconds; absent means the group's default.
fn timeout_of(body: &Value, default: u32) -> ApiResult<u32> {
    match body.get("timeout_ms") {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|millis| u32::try_from(millis).ok())
            .ok_or_else(|| ApiError::invalid_body("timeout_ms")),
    }
}

/// The key of a request body: absent or null keeps the saved key; text replaces it.
fn key_of(body: &Value) -> ApiResult<Option<ApiKey>> {
    match text_of(body, "key")? {
        None => Ok(None),
        Some(text) => ApiKey::new(&text).map(Some).map_err(refused),
    }
}

/// Whether the caller tested these exact values before saving.
fn tested_of(body: &Value) -> ApiResult<bool> {
    match body.get("tested") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(ApiError::invalid_body("tested")),
    }
}

/// `PUT /api/system/models/{group}`: saves a new version of the group. The body
/// carries the values, the `expected_version` the page last read, an optional
/// `note`, and an optional `key` (absent keeps the saved one).
///
/// # Errors
/// `VERSION_CONFLICT` (409) when the version moved, a `MODEL_*` or `JEV_CONFIG_*`
/// code for a refused value, `MODEL_KEY_UNAVAILABLE` (503) when no context secret
/// is set and a key must be sealed, and `INTERNAL` when the database fails.
pub async fn save(
    State(state): State<Arc<ControlState>>,
    Path(group): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SavedBody>> {
    let group = Group::parse(&group)?;
    let body: Value = json_body(&headers, &body)?;
    let expected = expected_version(&body)?;
    let note = note_from(&body)?;
    let tested = tested_of(&body)?;
    let key = key_of(&body)?;
    let sealer = state.key_sealer.as_ref();
    let version = match group {
        Group::Jev => {
            let spec = jev_spec(&body)?;
            store::save_jev(
                &state.pool,
                sealer,
                JevSave {
                    expected_version: expected,
                    spec,
                    key,
                    note,
                    tested,
                },
            )
            .await?
        }
        Group::Agent => {
            let spec = agent_spec(&body)?;
            store::save_agent(
                &state.pool,
                sealer,
                AgentSave {
                    expected_version: expected,
                    spec,
                    key,
                    note,
                    tested,
                },
            )
            .await?
        }
    };
    Ok(Json(SavedBody {
        group: group.name(),
        version,
    }))
}

/// `DELETE /api/system/models/jev?expected_version=N&note=…`: gives Jev back to the
/// environment. Allowed only when every online gateway holds an environment key,
/// so the calls do not stop. The version still counts up, and the history gets a
/// `revert_to_env` entry. The answer is the Jev group, as `GET` gives it.
///
/// # Errors
/// `MODEL_NO_ENVIRONMENT` (409) for the agent group, which has no environment
/// settings; `MODEL_ENV_KEY_MISSING` (409) when an online gateway, or none, has no
/// environment key; `VERSION_CONFLICT` (409) for a stale version.
pub async fn revert(
    State(state): State<Arc<ControlState>>,
    Path(group): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<JevGroupBody>> {
    if Group::parse(&group)? != Group::Jev {
        return Err(ApiError::new(StatusCode::CONFLICT, "MODEL_NO_ENVIRONMENT"));
    }
    let expected = query
        .get("expected_version")
        .and_then(|text| text.parse::<i64>().ok())
        .ok_or_else(|| ApiError::invalid_body("expected_version"))?;
    let note = query.get("note").filter(|text| !text.is_empty()).cloned();
    let now = chrono::Utc::now();
    let edges = edge_status_store::list(&state.pool).await?;
    let reports: Vec<JevConfigBody> = edges
        .iter()
        .filter(|edge| edge.is_online(now))
        .map(reported_config)
        .collect();
    let env_ready = !reports.is_empty()
        && reports
            .iter()
            .all(|report| report.env_available == Some(true));
    if !env_ready {
        return Err(ApiError::new(StatusCode::CONFLICT, "MODEL_ENV_KEY_MISSING"));
    }
    store::revert_jev_to_env(&state.pool, expected, note.as_deref()).await?;
    let rows = store::read(&state.pool).await?;
    Ok(Json(jev_state(&state, &rows.jev).await?))
}

/// `POST /api/system/models/{group}/test`: one minimal call with the values in the
/// body. A key left out is the saved one. The call is not written to the decision
/// log and is not counted against the learning agent's daily limit.
///
/// # Errors
/// `MODEL_TEST_RATE_LIMITED` (429) within ten seconds of the group's last test,
/// `MODEL_KEY_REQUIRED` (409) when no key is given or saved, the refusal codes of
/// the values, and `MODEL_KEY_UNAVAILABLE` (503) when a saved key cannot be opened.
pub async fn test(
    State(state): State<Arc<ControlState>>,
    Path(group): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<TestBody>> {
    let group = Group::parse(&group)?;
    let body: Value = json_body(&headers, &body)?;
    throttle_test(&state, group)?;
    let outcome = match group {
        Group::Jev => {
            let spec = jev_spec(&body)?;
            let key = match key_of(&body)? {
                Some(key) => key,
                None => saved_jev_key(&state, spec.endpoint()).await?,
            };
            let client = JevClient::from_spec(&spec, &key).map_err(client_refused)?;
            probe::jev(&client, Duration::from_millis(u64::from(spec.timeout_ms()))).await
        }
        Group::Agent => {
            let spec = agent_spec(&body)?;
            let model = spec.model().ok_or_else(|| refused(ConfigError::Model))?;
            let key = match key_of(&body)? {
                Some(key) => key,
                None => saved_agent_key(&state, spec.endpoint()).await?,
            };
            probe::chat(
                spec.endpoint(),
                &key,
                model,
                Duration::from_millis(u64::from(spec.timeout_ms())),
            )
            .await
        }
    };
    Ok(Json(TestBody::from(outcome)))
}

/// Refuses a second test of the same group within [`TEST_INTERVAL`].
fn throttle_test(state: &ControlState, group: Group) -> ApiResult<()> {
    let mut last = state
        .model_test_at
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    if last
        .get(group.name())
        .is_some_and(|at| now.duration_since(*at) < TEST_INTERVAL)
    {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "MODEL_TEST_RATE_LIMITED",
        ));
    }
    last.insert(group.name(), now);
    Ok(())
}

/// The refusal of a saved key for an address it was not saved for.
fn key_endpoint_changed() -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "MODEL_KEY_ENDPOINT_CHANGED").in_field("key")
}

/// The saved key when the call goes to the address the key was saved for.
fn saved_key_for(saved_endpoint: &str, endpoint: &str, key: ApiKey) -> ApiResult<ApiKey> {
    if saved_endpoint == endpoint {
        Ok(key)
    } else {
        Err(key_endpoint_changed())
    }
}

/// The saved Jev key, opened for a test that leaves the key out. It is given only
/// for the address it was saved for: a test of another address must bring its key,
/// so the saved one cannot be sent somewhere else.
async fn saved_jev_key(state: &ControlState, endpoint: &str) -> ApiResult<ApiKey> {
    let secret = store::load_jev(&state.pool, state.key_sealer.as_ref())
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "MODEL_KEY_REQUIRED").in_field("key"))?;
    saved_key_for(secret.spec.endpoint(), endpoint, secret.api_key)
}

/// The saved agent key, opened for a test that leaves the key out. The agent's
/// own key, or the Jev key when the agent shares it; only for the saved address.
async fn saved_agent_key(state: &ControlState, endpoint: &str) -> ApiResult<ApiKey> {
    let saved = store::load_agent(&state.pool, state.key_sealer.as_ref())
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "MODEL_KEY_REQUIRED").in_field("key"))?;
    saved_key_for(&saved.base_url, endpoint, saved.api_key)
}

/// `GET /api/system/models/{group}/history`: the newest versions first.
///
/// # Errors
/// `MODEL_GROUP_UNKNOWN` (404) for an unknown group; `INTERNAL` on database errors.
pub async fn history(
    State(state): State<Arc<ControlState>>,
    Path(group): Path<String>,
) -> ApiResult<Json<Vec<HistoryBody>>> {
    let group = Group::parse(&group)?;
    let entries = store::history(&state.pool, group.name(), HISTORY_LIMIT).await?;
    Ok(Json(entries.iter().map(HistoryBody::from).collect()))
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;
    use xshield_core::context::config::SiteSpec;

    use super::*;

    #[test]
    fn a_saved_key_is_given_only_for_the_address_it_was_saved_for() {
        let key = || ApiKey::new("sk-console-9f3a").expect("key");
        let saved = "https://api.typesafe.ai/v1/systemone";
        assert_eq!(
            saved_key_for(saved, saved, key())
                .expect("same address")
                .expose(),
            "sk-console-9f3a"
        );
        for other in [
            "https://collector.example.net/v1/systemone",
            "https://api.typesafe.ai/v1/systemone/",
            "http://api.typesafe.ai/v1/systemone",
        ] {
            let Err(refused) = saved_key_for(saved, other, key()) else {
                panic!("the saved key was given for {other}");
            };
            let response = axum::response::IntoResponse::into_response(refused);
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{other}");
        }
    }

    fn site(name: &str, agent: &str) -> SiteRecord {
        let text = format!(
            r#"{{
                "name": "{name}", "hosts": ["{name}.example.com"], "origin": "http://127.0.0.1:3000",
                "session": {{"cookie": "SESSIONID"}}, "entries": ["/login"], "bypass": [],
                "mode": "observe", "objects": {{"learning": {{"agent": {agent}}}}}
            }}"#
        );
        let now = DateTime::from_timestamp_millis(1_793_538_000_000).expect("time");
        SiteRecord {
            spec: SiteSpec::from_json(&text).expect("valid spec"),
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn the_sites_with_the_agent_on_or_asking_today_are_listed_with_their_share() {
        let sites = [
            site("alpha", r#"{"enabled": true, "daily_limit": 50}"#),
            site("beta", r#"{"enabled": false, "daily_limit": 20}"#),
            site("gamma", r#"{"enabled": false, "daily_limit": 20}"#),
        ];
        let per_site = [
            SiteDay {
                site: "beta".to_owned(),
                used: 3,
                failed: 1,
                last_call_millis: Some(1_000),
            },
            SiteDay {
                site: "removed".to_owned(),
                used: 9,
                failed: 0,
                last_call_millis: Some(2_000),
            },
        ];
        assert_eq!(
            agent_sites(&sites, &per_site, &[], 60_000),
            vec![
                AgentSiteBody {
                    site: "alpha".to_owned(),
                    enabled: true,
                    used: 0,
                    limit: 50,
                    failed: 0,
                    last_call_at: None,
                    full_days: 0,
                },
                AgentSiteBody {
                    site: "beta".to_owned(),
                    enabled: false,
                    used: 3,
                    limit: 20,
                    failed: 1,
                    last_call_at: rfc3339(1_000),
                    full_days: 0,
                },
            ]
        );
    }

    #[test]
    fn a_site_counts_its_full_days_back_from_yesterday_and_stops_at_the_first_short_day() {
        let sites = [
            site("alpha", r#"{"enabled": true, "daily_limit": 50}"#),
            site("beta", r#"{"enabled": true, "daily_limit": 20}"#),
        ];
        let history: Vec<SiteDayCount> = [
            ("alpha", 60_000, 50),
            ("alpha", 59_999, 50),
            ("alpha", 59_998, 50),
            ("alpha", 59_997, 49),
            ("alpha", 59_996, 50),
        ]
        .into_iter()
        .chain((59_993..=59_999).map(|day| ("beta", day, 20)))
        .map(|(site, day, used)| SiteDayCount {
            site: site.to_owned(),
            day,
            used,
        })
        .collect();

        let rows = agent_sites(&sites, &[], &history, 60_000);
        let full = |name: &str| {
            rows.iter()
                .find(|row| row.site == name)
                .map(|row| row.full_days)
        };
        // Today does not count, the short day ends alpha's run, and beta's run stops at a week.
        assert_eq!(full("alpha"), Some(2));
        assert_eq!(full("beta"), Some(7));
    }
}
