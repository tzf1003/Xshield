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
    context::config::{Mode, OnJevUnavailable},
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
        agent: agent_group(&rows),
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
fn agent_group(rows: &ModelRows) -> AgentGroupBody {
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
    }
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
                None => saved_jev_key(&state).await?,
            };
            let client = JevClient::from_spec(&spec, &key).map_err(client_refused)?;
            probe::jev(&client, Duration::from_millis(u64::from(spec.timeout_ms()))).await
        }
        Group::Agent => {
            let spec = agent_spec(&body)?;
            let model = spec.model().ok_or_else(|| refused(ConfigError::Model))?;
            let key = match key_of(&body)? {
                Some(key) => key,
                None => saved_agent_key(&state).await?,
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

/// The saved Jev key, opened for a test that leaves the key out.
async fn saved_jev_key(state: &ControlState) -> ApiResult<ApiKey> {
    store::load_jev(&state.pool, state.key_sealer.as_ref())
        .await?
        .map(|secret| secret.api_key)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "MODEL_KEY_REQUIRED").in_field("key"))
}

/// The saved agent key, opened for a test that leaves the key out. The agent's
/// own key, or the Jev key when the agent shares it.
async fn saved_agent_key(state: &ControlState) -> ApiResult<ApiKey> {
    store::load_agent(&state.pool, state.key_sealer.as_ref())
        .await?
        .map(|endpoint| endpoint.api_key)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "MODEL_KEY_REQUIRED").in_field("key"))
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
