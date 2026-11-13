//! Storage of the console's model settings (migration 0006, docs/03 section 3.3).
//!
//! The control plane writes these rows, and the gateway and the learning agent
//! read them. Every write runs in one transaction that locks the singleton row,
//! checks the version the operator saw, and writes one history row, so two tabs
//! saving at once get a conflict instead of a silent overwrite.
//!
//! Keys are sealed with [`crate::key_seal::KeySealer`]. Reading a key needs the
//! sealer; reading the settings does not.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row as _, Transaction, postgres::PgRow};
use xshield_core::model::{
    AgentProvider, AgentSpec, ApiKey, ConfigError, FieldChange, JEV_TIMEOUT_MS, JevRoute, JevSpec,
    ModelEndpoint, changed_fields,
};

use crate::key_seal::{KeySealer, SealError};

/// Associated data that binds a sealed Jev key to its column.
const JEV_KEY_COLUMN: &str = "model_config.jev_key";
/// Associated data that binds a sealed agent key to its column.
const AGENT_KEY_COLUMN: &str = "model_config.agent_key";
/// Longest operator note, in characters (the console and the API share this limit).
pub const NOTE_MAX_CHARS: usize = 200;

const SELECT_ROW: &str = "SELECT jev_version, jev_route, jev_endpoint, jev_model, jev_timeout_ms,
        jev_key, jev_key_last4, jev_key_at, jev_saved_at,
        agent_version, agent_provider, agent_endpoint, agent_model, agent_timeout_ms,
        agent_share_key, agent_key, agent_key_last4, agent_key_at, agent_saved_at
    FROM model_config WHERE id = 1";

/// The same row, locked for the rest of a transaction.
const SELECT_ROW_FOR_UPDATE: &str = "SELECT jev_version, jev_route, jev_endpoint, jev_model,
        jev_timeout_ms, jev_key, jev_key_last4, jev_key_at, jev_saved_at,
        agent_version, agent_provider, agent_endpoint, agent_model, agent_timeout_ms,
        agent_share_key, agent_key, agent_key_last4, agent_key_at, agent_saved_at
    FROM model_config WHERE id = 1 FOR UPDATE";

/// Why a model setting could not be read or written. The codes are stable.
#[derive(Debug)]
pub enum ModelConfigError {
    /// The database failed. The cause is not included, to keep it out of responses.
    Database(sqlx::Error),
    /// A stored value does not decode. Writes are checked first, so this means
    /// the row was changed outside the console.
    Stored,
    /// The process has no context secret, so a sealed key cannot be opened or sealed.
    KeyUnavailable,
    /// A stored key does not open, or it is no longer a valid key.
    KeyUnreadable,
    /// The Jev group has no key yet, and the save brought none.
    KeyRequired,
    /// The address changed and the save brought no key: a saved key goes only to
    /// the address it was saved for.
    KeyEndpointChanged,
    /// The note is longer than [`NOTE_MAX_CHARS`].
    NoteTooLong,
    /// The version the operator saw is no longer the saved one.
    Conflict {
        /// The version that is saved now.
        current: i64,
    },
    /// The values were refused, for the reason given.
    Refused(ConfigError),
}

impl ModelConfigError {
    /// The stable code of the failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Database(_) => "MODEL_STORE_UNAVAILABLE",
            Self::Stored => "MODEL_STORE_INVALID",
            Self::KeyUnavailable => "MODEL_KEY_UNAVAILABLE",
            Self::KeyUnreadable => "MODEL_KEY_UNREADABLE",
            Self::KeyRequired => "MODEL_KEY_REQUIRED",
            Self::KeyEndpointChanged => "MODEL_KEY_ENDPOINT_CHANGED",
            Self::NoteTooLong => "MODEL_NOTE_INVALID",
            Self::Conflict { .. } => "VERSION_CONFLICT",
            Self::Refused(reason) => reason.code(),
        }
    }
}

impl std::fmt::Display for ModelConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ModelConfigError {}

impl From<sqlx::Error> for ModelConfigError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<ConfigError> for ModelConfigError {
    fn from(error: ConfigError) -> Self {
        Self::Refused(error)
    }
}

/// The saved Jev group, without its key.
#[derive(Debug, Clone, PartialEq)]
pub struct JevRecord {
    /// The saved version; 0 when the console has never saved this group.
    pub version: i64,
    /// The saved settings, or the route defaults at version 0.
    pub spec: JevSpec,
    /// The last four characters of the saved key, if the console holds one.
    pub key_last4: Option<String>,
    /// When the key was last replaced.
    pub key_at: Option<DateTime<Utc>>,
    /// When the group was last saved.
    pub saved_at: Option<DateTime<Utc>>,
}

/// The saved learning agent group, without its key.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRecord {
    /// The saved version; 0 when the group has never been saved.
    pub version: i64,
    /// The saved settings, or the defaults at version 0.
    pub spec: AgentSpec,
    /// The last four characters of the key in use, if one is set.
    pub key_last4: Option<String>,
    /// When the key was last replaced.
    pub key_at: Option<DateTime<Utc>>,
    /// When the group was last saved.
    pub saved_at: Option<DateTime<Utc>>,
}

/// Both groups, without their keys.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelRows {
    /// The Jev judgement model.
    pub jev: JevRecord,
    /// The learning agent's model.
    pub agent: AgentRecord,
}

/// The Jev settings the console holds, with the key opened. The gateway uses
/// these in place of its environment when `api_key` is present.
pub struct JevSecret {
    /// The saved version.
    pub version: i64,
    /// The saved settings.
    pub spec: JevSpec,
    /// The key, opened.
    pub api_key: ApiKey,
}

/// One saved change in the history, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryChange {
    /// The field name.
    pub field: String,
    /// The value before.
    pub from: String,
    /// The value after.
    pub to: String,
}

/// One version of a group, as the history page shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    /// The version.
    pub version: i64,
    /// `save` or `revert_to_env`.
    pub change: String,
    /// The non-secret configuration of this version, for restoring it.
    pub config: Value,
    /// The fields that changed, the key included as its last four characters.
    pub changes: Vec<HistoryChange>,
    /// `replaced`, `cleared`, or `None` when the key was kept.
    pub key_change: Option<String>,
    /// The key in use after this version.
    pub key_last4: Option<String>,
    /// The operator's note.
    pub note: Option<String>,
    /// Whether the operator's test had succeeded before the save.
    pub tested: bool,
    /// When the version was saved.
    pub changed_at: DateTime<Utc>,
}

/// A Jev save: the operator's values, the version they were based on, and an
/// optional new key.
pub struct JevSave {
    /// The version the operator's form was loaded at.
    pub expected_version: i64,
    /// The checked settings.
    pub spec: JevSpec,
    /// A replacement key; `None` keeps the saved one.
    pub key: Option<ApiKey>,
    /// The operator's note, if any.
    pub note: Option<String>,
    /// Whether the operator's test of these values had succeeded.
    pub tested: bool,
}

/// A learning agent save, the same shape as [`JevSave`].
pub struct AgentSave {
    /// The version the operator's form was loaded at.
    pub expected_version: i64,
    /// The checked settings, including whether the Jev key is shared.
    pub spec: AgentSpec,
    /// A replacement key; `None` keeps the saved one. Must be `None` when the key is shared.
    pub key: Option<ApiKey>,
    /// The operator's note, if any.
    pub note: Option<String>,
    /// Whether the operator's test of these values had succeeded.
    pub tested: bool,
}

/// The stored row, as it is.
struct ModelRow {
    jev_version: i64,
    jev_route: String,
    jev_endpoint: Option<String>,
    jev_model: Option<String>,
    jev_timeout_ms: i32,
    jev_key: Option<Vec<u8>>,
    jev_key_last4: Option<String>,
    jev_key_at: Option<DateTime<Utc>>,
    jev_saved_at: Option<DateTime<Utc>>,
    agent_version: i64,
    agent_provider: String,
    agent_endpoint: Option<String>,
    agent_model: Option<String>,
    agent_timeout_ms: i32,
    agent_share_key: bool,
    agent_key: Option<Vec<u8>>,
    agent_key_last4: Option<String>,
    agent_key_at: Option<DateTime<Utc>>,
    agent_saved_at: Option<DateTime<Utc>>,
}

impl ModelRow {
    fn from_pg(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            jev_version: row.try_get("jev_version")?,
            jev_route: row.try_get("jev_route")?,
            jev_endpoint: row.try_get("jev_endpoint")?,
            jev_model: row.try_get("jev_model")?,
            jev_timeout_ms: row.try_get("jev_timeout_ms")?,
            jev_key: row.try_get("jev_key")?,
            jev_key_last4: row.try_get("jev_key_last4")?,
            jev_key_at: row.try_get("jev_key_at")?,
            jev_saved_at: row.try_get("jev_saved_at")?,
            agent_version: row.try_get("agent_version")?,
            agent_provider: row.try_get("agent_provider")?,
            agent_endpoint: row.try_get("agent_endpoint")?,
            agent_model: row.try_get("agent_model")?,
            agent_timeout_ms: row.try_get("agent_timeout_ms")?,
            agent_share_key: row.try_get("agent_share_key")?,
            agent_key: row.try_get("agent_key")?,
            agent_key_last4: row.try_get("agent_key_last4")?,
            agent_key_at: row.try_get("agent_key_at")?,
            agent_saved_at: row.try_get("agent_saved_at")?,
        })
    }

    fn jev_spec(&self) -> Result<JevSpec, ModelConfigError> {
        let route = JevRoute::parse(&self.jev_route).ok_or(ModelConfigError::Stored)?;
        let timeout = u32::try_from(self.jev_timeout_ms).map_err(|_| ModelConfigError::Stored)?;
        JevSpec::new(
            route,
            self.jev_endpoint.as_deref(),
            self.jev_model.as_deref(),
            timeout,
        )
        .map_err(|_| ModelConfigError::Stored)
    }

    fn agent_spec(&self) -> Result<AgentSpec, ModelConfigError> {
        let provider =
            AgentProvider::parse(&self.agent_provider).ok_or(ModelConfigError::Stored)?;
        let timeout = u32::try_from(self.agent_timeout_ms).map_err(|_| ModelConfigError::Stored)?;
        AgentSpec::new(
            provider,
            self.agent_endpoint.as_deref(),
            self.agent_model.as_deref(),
            timeout,
            self.agent_share_key,
        )
        .map_err(|_| ModelConfigError::Stored)
    }

    fn jev_record(&self) -> Result<JevRecord, ModelConfigError> {
        Ok(JevRecord {
            version: self.jev_version,
            spec: self.jev_spec()?,
            key_last4: self.jev_key_last4.clone(),
            key_at: self.jev_key_at,
            saved_at: self.jev_saved_at,
        })
    }

    fn agent_record(&self) -> Result<AgentRecord, ModelConfigError> {
        Ok(AgentRecord {
            version: self.agent_version,
            spec: self.agent_spec()?,
            key_last4: self.agent_key_last4.clone(),
            key_at: self.agent_key_at,
            saved_at: self.agent_saved_at,
        })
    }
}

async fn fetch_row(pool: &PgPool) -> Result<ModelRow, ModelConfigError> {
    let row = sqlx::query(SELECT_ROW).fetch_one(pool).await?;
    Ok(ModelRow::from_pg(&row)?)
}

async fn lock_row(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<ModelRow, ModelConfigError> {
    let row = sqlx::query(SELECT_ROW_FOR_UPDATE)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(ModelRow::from_pg(&row)?)
}

/// Reads both groups without their keys.
///
/// # Errors
/// [`ModelConfigError::Database`] or [`ModelConfigError::Stored`].
pub async fn read(pool: &PgPool) -> Result<ModelRows, ModelConfigError> {
    let row = fetch_row(pool).await?;
    Ok(ModelRows {
        jev: row.jev_record()?,
        agent: row.agent_record()?,
    })
}

/// Opens the saved Jev key, when the console holds one. `None` means the
/// gateway should read its environment instead.
///
/// # Errors
/// [`ModelConfigError::KeyUnavailable`] when a key is stored but no sealer is
/// given, [`ModelConfigError::KeyUnreadable`] when it does not open.
pub async fn load_jev(
    pool: &PgPool,
    sealer: Option<&KeySealer>,
) -> Result<Option<JevSecret>, ModelConfigError> {
    let row = fetch_row(pool).await?;
    let Some(stored) = row.jev_key.as_deref() else {
        return Ok(None);
    };
    Ok(Some(JevSecret {
        version: row.jev_version,
        spec: row.jev_spec()?,
        api_key: open_key(sealer, JEV_KEY_COLUMN, stored)?,
    }))
}

/// The learning agent's model endpoint, or `None` while it is not fully
/// configured: no model name, no key, or a shared key whose Jev side is not on
/// the gateway. Called by the control process, which runs the learning agent.
///
/// # Errors
/// [`ModelConfigError::KeyUnavailable`] when a key is needed but no sealer is
/// given, and the database and decoding errors of [`read`].
pub async fn load_agent(
    pool: &PgPool,
    sealer: Option<&KeySealer>,
) -> Result<Option<ModelEndpoint>, ModelConfigError> {
    let row = fetch_row(pool).await?;
    let spec = row.agent_spec()?;
    let Some(model) = spec.model() else {
        return Ok(None);
    };
    let api_key = if spec.share_key_with_jev() {
        if row.jev_route != JevRoute::Gateway.as_str() {
            return Ok(None);
        }
        match row.jev_key.as_deref() {
            Some(stored) => open_key(sealer, JEV_KEY_COLUMN, stored)?,
            None => return Ok(None),
        }
    } else {
        match row.agent_key.as_deref() {
            Some(stored) => open_key(sealer, AGENT_KEY_COLUMN, stored)?,
            None => return Ok(None),
        }
    };
    Ok(Some(ModelEndpoint {
        base_url: spec.endpoint().to_owned(),
        model: model.to_owned(),
        api_key,
        timeout_ms: spec.timeout_ms(),
    }))
}

/// Saves the Jev group. Returns the new version.
///
/// The first save must bring a key, because the console does not take over a
/// group that only has the environment's key. A key shared with the agent
/// blocks a route change away from the gateway.
///
/// # Errors
/// [`ModelConfigError::Conflict`] when `expected_version` is stale,
/// [`ModelConfigError::KeyRequired`], [`ModelConfigError::Refused`] for a
/// shared key, [`ModelConfigError::KeyUnavailable`] without a sealer, and the
/// database errors.
pub async fn save_jev(
    pool: &PgPool,
    sealer: Option<&KeySealer>,
    save: JevSave,
) -> Result<i64, ModelConfigError> {
    check_note(save.note.as_deref())?;
    let mut transaction = pool.begin().await?;
    let current = lock_row(&mut transaction).await?;
    if current.jev_version != save.expected_version {
        return Err(ModelConfigError::Conflict {
            current: current.jev_version,
        });
    }
    if current.jev_key.is_none() && save.key.is_none() {
        return Err(ModelConfigError::KeyRequired);
    }
    if current.agent_share_key && save.spec.route() != JevRoute::Gateway {
        return Err(ConfigError::Share.into());
    }
    let previous = current.jev_spec()?;
    if save.key.is_none() && previous.endpoint() != save.spec.endpoint() {
        return Err(ModelConfigError::KeyEndpointChanged);
    }
    let mut changes = changed_fields(&previous.values(), &save.spec.values());
    let stored = seal_optional(sealer, JEV_KEY_COLUMN, save.key.as_ref())?;
    let key_last4 = save
        .key
        .as_ref()
        .map_or_else(|| current.jev_key_last4.clone(), |key| Some(key.last4()));
    if save.key.is_some() {
        changes.push(key_change(
            current.jev_key_last4.as_deref(),
            key_last4.as_deref(),
        ));
    }
    let timeout = i32::try_from(save.spec.timeout_ms())
        .map_err(|_| ModelConfigError::Refused(ConfigError::Timeout))?;
    let endpoint = (save.spec.route() == JevRoute::Custom).then(|| save.spec.endpoint().to_owned());
    let new_version: i64 = sqlx::query_scalar(
        "UPDATE model_config SET
            jev_version = jev_version + 1,
            jev_route = $1, jev_endpoint = $2, jev_model = $3, jev_timeout_ms = $4,
            jev_key = COALESCE($5::bytea, jev_key),
            jev_key_last4 = COALESCE($6::text, jev_key_last4),
            jev_key_at = CASE WHEN $5::bytea IS NULL THEN jev_key_at ELSE now() END,
            jev_saved_at = now()
         WHERE id = 1
         RETURNING jev_version",
    )
    .bind(save.spec.route().as_str())
    .bind(endpoint)
    .bind(save.spec.model().to_owned())
    .bind(timeout)
    .bind(stored.as_deref())
    .bind(save.key.as_ref().map(ApiKey::last4))
    .fetch_one(&mut *transaction)
    .await?;
    insert_history(
        &mut transaction,
        HistoryWrite {
            group: "jev",
            version: new_version,
            change: "save",
            config: jev_config(&save.spec),
            changes: &changes,
            key_change: save.key.is_some().then_some("replaced"),
            key_last4: key_last4.as_deref(),
            note: save.note.as_deref(),
            tested: save.tested,
        },
    )
    .await?;
    transaction.commit().await?;
    Ok(new_version)
}

/// Saves the learning agent group. Returns the new version.
///
/// # Errors
/// As [`save_jev`]; a key given together with a shared key is refused.
pub async fn save_agent(
    pool: &PgPool,
    sealer: Option<&KeySealer>,
    save: AgentSave,
) -> Result<i64, ModelConfigError> {
    check_note(save.note.as_deref())?;
    let mut transaction = pool.begin().await?;
    let current = lock_row(&mut transaction).await?;
    if current.agent_version != save.expected_version {
        return Err(ModelConfigError::Conflict {
            current: current.agent_version,
        });
    }
    save.spec.check_share(&current.jev_spec()?)?;
    if save.spec.share_key_with_jev() && save.key.is_some() {
        return Err(ConfigError::Share.into());
    }
    let previous = current.agent_spec()?;
    let shared = save.spec.share_key_with_jev();
    // A shared key goes only to the fixed address of the gateway line (`check_share`).
    if !shared
        && save.key.is_none()
        && current.agent_key.is_some()
        && previous.endpoint() != save.spec.endpoint()
    {
        return Err(ModelConfigError::KeyEndpointChanged);
    }
    let mut changes = changed_fields(&previous.values(), &save.spec.values());
    let stored = seal_optional(sealer, AGENT_KEY_COLUMN, save.key.as_ref())?;
    let key_last4 = if shared {
        None
    } else {
        save.key
            .as_ref()
            .map_or_else(|| current.agent_key_last4.clone(), |key| Some(key.last4()))
    };
    // Sharing drops the agent's own key, which the history records as cleared.
    let key_event = if save.key.is_some() {
        Some("replaced")
    } else if shared && current.agent_key_last4.is_some() {
        Some("cleared")
    } else {
        None
    };
    if key_event.is_some() {
        changes.push(key_change(
            current.agent_key_last4.as_deref(),
            key_last4.as_deref(),
        ));
    }
    let timeout = i32::try_from(save.spec.timeout_ms())
        .map_err(|_| ModelConfigError::Refused(ConfigError::Timeout))?;
    let endpoint =
        (save.spec.provider() == AgentProvider::Custom).then(|| save.spec.endpoint().to_owned());
    let new_version: i64 = sqlx::query_scalar(
        "UPDATE model_config SET
            agent_version = agent_version + 1,
            agent_provider = $1, agent_endpoint = $2, agent_model = $3,
            agent_timeout_ms = $4, agent_share_key = $5,
            agent_key = CASE WHEN $5 THEN NULL ELSE COALESCE($6::bytea, agent_key) END,
            agent_key_last4 = CASE WHEN $5 THEN NULL ELSE COALESCE($7::text, agent_key_last4) END,
            agent_key_at = CASE WHEN $5 THEN NULL
                WHEN $6::bytea IS NULL THEN agent_key_at ELSE now() END,
            agent_saved_at = now()
         WHERE id = 1
         RETURNING agent_version",
    )
    .bind(save.spec.provider().as_str())
    .bind(endpoint)
    .bind(save.spec.model().map(str::to_owned))
    .bind(timeout)
    .bind(shared)
    .bind(stored.as_deref())
    .bind(save.key.as_ref().map(ApiKey::last4))
    .fetch_one(&mut *transaction)
    .await?;
    insert_history(
        &mut transaction,
        HistoryWrite {
            group: "agent",
            version: new_version,
            change: "save",
            config: agent_config(&save.spec),
            changes: &changes,
            key_change: key_event,
            key_last4: key_last4.as_deref(),
            note: save.note.as_deref(),
            tested: save.tested,
        },
    )
    .await?;
    transaction.commit().await?;
    Ok(new_version)
}

/// Gives the Jev group back to the environment: the console drops its settings
/// and its key, and the gateway reads its environment again. Returns the new
/// version.
///
/// # Errors
/// [`ModelConfigError::Conflict`] for a stale version, and
/// [`ModelConfigError::Refused`] while the agent shares the Jev key.
pub async fn revert_jev_to_env(
    pool: &PgPool,
    expected_version: i64,
    note: Option<&str>,
) -> Result<i64, ModelConfigError> {
    check_note(note)?;
    let mut transaction = pool.begin().await?;
    let current = lock_row(&mut transaction).await?;
    if current.jev_version != expected_version {
        return Err(ModelConfigError::Conflict {
            current: current.jev_version,
        });
    }
    if current.agent_share_key {
        return Err(ConfigError::Share.into());
    }
    let previous = current.jev_spec()?;
    let defaults = JevSpec::new(JevRoute::Gateway, None, None, JEV_TIMEOUT_MS)?;
    let mut changes = changed_fields(&previous.values(), &defaults.values());
    if current.jev_key.is_some() {
        changes.push(key_change(current.jev_key_last4.as_deref(), None));
    }
    let new_version: i64 = sqlx::query_scalar(
        "UPDATE model_config SET
            jev_version = jev_version + 1,
            jev_route = 'gateway', jev_endpoint = NULL, jev_model = NULL,
            jev_timeout_ms = $1, jev_key = NULL, jev_key_last4 = NULL, jev_key_at = NULL,
            jev_saved_at = now()
         WHERE id = 1
         RETURNING jev_version",
    )
    .bind(i32::try_from(JEV_TIMEOUT_MS).unwrap_or(i32::MAX))
    .fetch_one(&mut *transaction)
    .await?;
    insert_history(
        &mut transaction,
        HistoryWrite {
            group: "jev",
            version: new_version,
            change: "revert_to_env",
            config: jev_config(&defaults),
            changes: &changes,
            key_change: current.jev_key.is_some().then_some("cleared"),
            key_last4: None,
            note,
            tested: false,
        },
    )
    .await?;
    transaction.commit().await?;
    Ok(new_version)
}

/// The most recent versions of a group, newest first.
///
/// # Errors
/// [`ModelConfigError::Database`] when the query fails.
pub async fn history(
    pool: &PgPool,
    group: &str,
    limit: i64,
) -> Result<Vec<HistoryEntry>, ModelConfigError> {
    let rows = sqlx::query(
        "SELECT version, change, config, changes, key_change, key_last4, note, tested, changed_at
         FROM model_config_history WHERE model_group = $1
         ORDER BY version DESC LIMIT $2",
    )
    .bind(group)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            let changes: Value = row.try_get("changes")?;
            Ok(HistoryEntry {
                version: row.try_get("version")?,
                change: row.try_get("change")?,
                config: row.try_get("config")?,
                changes: history_changes(&changes),
                key_change: row.try_get("key_change")?,
                key_last4: row.try_get("key_last4")?,
                note: row.try_get("note")?,
                tested: row.try_get("tested")?,
                changed_at: row.try_get("changed_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(ModelConfigError::from)
}

fn history_changes(value: &Value) -> Vec<HistoryChange> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(HistoryChange {
                        field: item.get("field")?.as_str()?.to_owned(),
                        from: item.get("from")?.as_str()?.to_owned(),
                        to: item.get("to")?.as_str()?.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One history row to write.
struct HistoryWrite<'a> {
    group: &'a str,
    version: i64,
    change: &'a str,
    config: Value,
    changes: &'a [FieldChange],
    key_change: Option<&'a str>,
    key_last4: Option<&'a str>,
    note: Option<&'a str>,
    tested: bool,
}

async fn insert_history(
    transaction: &mut Transaction<'_, Postgres>,
    write: HistoryWrite<'_>,
) -> Result<(), ModelConfigError> {
    let changes: Vec<Value> = write
        .changes
        .iter()
        .map(|change| json!({ "field": change.field, "from": change.from, "to": change.to }))
        .collect();
    sqlx::query(
        "INSERT INTO model_config_history
            (model_group, version, change, config, changes, key_change, key_last4, note, tested)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(write.group)
    .bind(write.version)
    .bind(write.change)
    .bind(write.config)
    .bind(Value::Array(changes))
    .bind(write.key_change)
    .bind(write.key_last4)
    .bind(write.note)
    .bind(write.tested)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The history entry for a key: its last four characters before and after.
fn key_change(before: Option<&str>, after: Option<&str>) -> FieldChange {
    FieldChange {
        field: "key",
        from: before.unwrap_or_default().to_owned(),
        to: after.unwrap_or_default().to_owned(),
    }
}

fn jev_config(spec: &JevSpec) -> Value {
    json!({
        "route": spec.route().as_str(),
        "endpoint": spec.endpoint(),
        "model": spec.model(),
        "timeout_ms": spec.timeout_ms(),
    })
}

fn agent_config(spec: &AgentSpec) -> Value {
    json!({
        "provider": spec.provider().as_str(),
        "endpoint": spec.endpoint(),
        "model": spec.model(),
        "timeout_ms": spec.timeout_ms(),
        "share_key_with_jev": spec.share_key_with_jev(),
    })
}

fn check_note(note: Option<&str>) -> Result<(), ModelConfigError> {
    match note {
        Some(text) if text.chars().count() > NOTE_MAX_CHARS => Err(ModelConfigError::NoteTooLong),
        _ => Ok(()),
    }
}

fn seal_optional(
    sealer: Option<&KeySealer>,
    column: &str,
    key: Option<&ApiKey>,
) -> Result<Option<Vec<u8>>, ModelConfigError> {
    key.map(|key| seal(sealer, column, key.expose()))
        .transpose()
}

fn seal(
    sealer: Option<&KeySealer>,
    column: &str,
    plaintext: &str,
) -> Result<Vec<u8>, ModelConfigError> {
    let sealer = sealer.ok_or(ModelConfigError::KeyUnavailable)?;
    sealer
        .seal(column, plaintext.as_bytes())
        .map_err(|error| match error {
            SealError::Random | SealError::Seal | SealError::SecretTooShort => {
                ModelConfigError::KeyUnavailable
            }
            SealError::Layout | SealError::Open => ModelConfigError::KeyUnreadable,
        })
}

fn open_key(
    sealer: Option<&KeySealer>,
    column: &str,
    stored: &[u8],
) -> Result<ApiKey, ModelConfigError> {
    let sealer = sealer.ok_or(ModelConfigError::KeyUnavailable)?;
    let text = sealer
        .open(column, stored)
        .map_err(|_| ModelConfigError::KeyUnreadable)?;
    ApiKey::new(&text).map_err(|_| ModelConfigError::KeyUnreadable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_core::model::{AGENT_TIMEOUT_MS, GATEWAY_AGENT_ENDPOINT};

    #[test]
    fn every_error_has_a_stable_code_and_no_detail() {
        assert_eq!(ModelConfigError::KeyRequired.code(), "MODEL_KEY_REQUIRED");
        assert_eq!(
            ModelConfigError::KeyEndpointChanged.code(),
            "MODEL_KEY_ENDPOINT_CHANGED"
        );
        assert_eq!(
            ModelConfigError::Conflict { current: 7 }.code(),
            "VERSION_CONFLICT"
        );
        assert_eq!(
            ModelConfigError::Refused(ConfigError::Share).code(),
            "MODEL_KEY_SHARE_INVALID"
        );
        assert_eq!(
            ModelConfigError::KeyUnreadable.to_string(),
            "MODEL_KEY_UNREADABLE"
        );
    }

    #[test]
    fn history_changes_skip_malformed_items() {
        let value = json!([
            { "field": "model", "from": "a", "to": "b" },
            { "field": "broken" },
        ]);
        assert_eq!(
            history_changes(&value),
            vec![HistoryChange {
                field: "model".to_owned(),
                from: "a".to_owned(),
                to: "b".to_owned(),
            }]
        );
        assert!(history_changes(&Value::Null).is_empty());
    }

    #[test]
    fn notes_are_limited_in_characters() {
        assert!(check_note(Some(&"界".repeat(NOTE_MAX_CHARS))).is_ok());
        assert!(matches!(
            check_note(Some(&"界".repeat(NOTE_MAX_CHARS + 1))),
            Err(ModelConfigError::NoteTooLong)
        ));
    }

    #[test]
    fn a_key_without_a_sealer_is_unavailable_not_unreadable() {
        let key = ApiKey::new("sk-test-1234").expect("key");
        assert!(matches!(
            seal_optional(None, AGENT_KEY_COLUMN, Some(&key)),
            Err(ModelConfigError::KeyUnavailable)
        ));
        assert!(matches!(
            open_key(None, JEV_KEY_COLUMN, &[0_u8; 40]),
            Err(ModelConfigError::KeyUnavailable)
        ));
    }

    #[test]
    fn the_agent_default_timeout_matches_the_core_default() {
        assert_eq!(xshield_core::model::AGENT_TIMEOUT_MS, 30_000);
    }

    // The stable code of a refused write.
    fn refusal<T>(result: Result<T, ModelConfigError>) -> &'static str {
        match result {
            Ok(_) => panic!("the write should have been refused"),
            Err(error) => error.code(),
        }
    }

    fn versions(entries: &[HistoryEntry]) -> Vec<i64> {
        entries.iter().map(|entry| entry.version).collect()
    }

    fn jev(route: JevRoute, timeout_ms: u32) -> JevSpec {
        JevSpec::new(route, None, None, timeout_ms).expect("a valid Jev spec")
    }

    fn jev_save(expected_version: i64, spec: JevSpec, key: Option<&str>) -> JevSave {
        JevSave {
            expected_version,
            spec,
            key: key.map(|text| ApiKey::new(text).expect("a valid test key")),
            note: None,
            tested: false,
        }
    }

    // The learning agent on the gateway, with a model name, optionally sharing the Jev key.
    fn agent(share_key_with_jev: bool) -> AgentSpec {
        AgentSpec::new(
            AgentProvider::Gateway,
            None,
            Some("openai/gpt-4o-mini"),
            AGENT_TIMEOUT_MS,
            share_key_with_jev,
        )
        .expect("a valid agent spec")
    }

    fn agent_save(expected_version: i64, spec: AgentSpec, key: Option<&str>) -> AgentSave {
        AgentSave {
            expected_version,
            spec,
            key: key.map(|text| ApiKey::new(text).expect("a valid test key")),
            note: None,
            tested: false,
        }
    }

    async fn connect_test_pool() -> PgPool {
        let url = std::env::var("XSHIELD_TEST_DATABASE_URL").expect("XSHIELD_TEST_DATABASE_URL");
        PgPool::connect(&url).await.expect("connect")
    }

    // The database tests share one singleton row, so they run as one ordered scenario.
    // It needs a freshly migrated database; scripts/test_postgres.sh makes one.
    #[allow(clippy::too_many_lines)] // One ordered scenario over one shared row; splitting it would hide the order.
    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_TEST_DATABASE_URL)"]
    async fn the_model_settings_are_saved_refused_and_reverted_in_order() {
        let pool = connect_test_pool().await;
        let sealer = KeySealer::from_context_secret(&[7_u8; 32]).expect("a 32-byte secret");
        let other = KeySealer::from_context_secret(&[8_u8; 32]).expect("a 32-byte secret");

        let start = read(&pool).await.expect("read");
        assert_eq!(
            (start.jev.version, start.agent.version),
            (0, 0),
            "the model settings test needs a freshly migrated database"
        );
        assert!(
            load_jev(&pool, Some(&sealer))
                .await
                .expect("load")
                .is_none()
        );
        assert!(
            load_agent(&pool, Some(&sealer))
                .await
                .expect("load")
                .is_none()
        );

        // Refusals come before any write.
        let gateway = || jev(JevRoute::Gateway, JEV_TIMEOUT_MS);
        assert_eq!(
            refusal(save_jev(&pool, Some(&sealer), jev_save(0, gateway(), None)).await),
            "MODEL_KEY_REQUIRED"
        );
        let mut long_note = jev_save(0, gateway(), Some("sk-console-9f3a"));
        long_note.note = Some("界".repeat(NOTE_MAX_CHARS + 1));
        assert_eq!(
            refusal(save_jev(&pool, Some(&sealer), long_note).await),
            "MODEL_NOTE_INVALID"
        );
        assert!(matches!(
            save_jev(
                &pool,
                Some(&sealer),
                jev_save(7, gateway(), Some("sk-console-9f3a"))
            )
            .await,
            Err(ModelConfigError::Conflict { current: 0 })
        ));
        assert!(matches!(
            revert_jev_to_env(&pool, 7, None).await,
            Err(ModelConfigError::Conflict { current: 0 })
        ));

        // The first save brings the key. It is stored sealed and opens only with its sealer.
        let mut first = jev_save(0, gateway(), Some("sk-console-9f3a"));
        first.note = Some("first key".to_owned());
        first.tested = true;
        assert_eq!(
            save_jev(&pool, Some(&sealer), first)
                .await
                .expect("first save"),
            1
        );
        let saved = read(&pool).await.expect("read").jev;
        assert_eq!(saved.version, 1);
        assert_eq!(saved.key_last4.as_deref(), Some("9f3a"));
        let key_at = saved.key_at.expect("the key time is set");
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT jev_key FROM model_config WHERE id = 1")
                .fetch_one(&pool)
                .await
                .expect("the stored key row");
        let stored = stored.expect("a sealed key is stored");
        assert!(
            !stored
                .windows(b"sk-console-9f3a".len())
                .any(|window| window == b"sk-console-9f3a"),
            "the sealed key must not contain the plaintext"
        );
        let secret = load_jev(&pool, Some(&sealer))
            .await
            .expect("load")
            .expect("a key is stored");
        assert_eq!(secret.version, 1);
        assert_eq!(secret.api_key.expose(), "sk-console-9f3a");
        assert!(matches!(
            load_jev(&pool, None).await,
            Err(ModelConfigError::KeyUnavailable)
        ));
        assert!(matches!(
            load_jev(&pool, Some(&other)).await,
            Err(ModelConfigError::KeyUnreadable)
        ));

        // The saved key goes only to the address it was saved for: another route
        // has another address, so a save of it must bring its key.
        assert_eq!(
            refusal(
                save_jev(
                    &pool,
                    Some(&sealer),
                    jev_save(1, jev(JevRoute::Direct, 3_000), None)
                )
                .await
            ),
            "MODEL_KEY_ENDPOINT_CHANGED"
        );

        // A save without a key keeps the saved one, and changes the timeout.
        let slower = jev_save(1, jev(JevRoute::Gateway, 3_000), None);
        assert_eq!(
            save_jev(&pool, Some(&sealer), slower)
                .await
                .expect("save without a key"),
            2
        );
        let direct = read(&pool).await.expect("read").jev;
        assert_eq!(direct.spec.route(), JevRoute::Gateway);
        assert_eq!(direct.spec.timeout_ms(), 3_000);
        assert_eq!(direct.key_last4.as_deref(), Some("9f3a"));
        assert_eq!(direct.key_at, Some(key_at));
        let kept = load_jev(&pool, Some(&sealer))
            .await
            .expect("load")
            .expect("the key is kept");
        assert_eq!(kept.api_key.expose(), "sk-console-9f3a");

        // A new key replaces the old one. The note and the test result are kept.
        let mut rotated = jev_save(2, gateway(), Some("sk-console-abcd"));
        rotated.note = Some("rotated".to_owned());
        rotated.tested = true;
        assert_eq!(
            save_jev(&pool, Some(&sealer), rotated)
                .await
                .expect("rotate"),
            3
        );
        let rotated_secret = load_jev(&pool, Some(&sealer))
            .await
            .expect("load")
            .expect("a key is stored");
        assert_eq!(rotated_secret.api_key.expose(), "sk-console-abcd");

        // The agent keeps its own key until it shares the Jev key.
        let mut own = agent_save(0, agent(false), Some("sk-agent-7777"));
        own.note = Some("own key".to_owned());
        assert_eq!(
            save_agent(&pool, Some(&sealer), own)
                .await
                .expect("agent save"),
            1
        );
        let agent_own = read(&pool).await.expect("read").agent;
        assert_eq!(agent_own.key_last4.as_deref(), Some("7777"));
        let endpoint = load_agent(&pool, Some(&sealer))
            .await
            .expect("load")
            .expect("configured");
        assert_eq!(endpoint.base_url, GATEWAY_AGENT_ENDPOINT);
        assert_eq!(endpoint.model, "openai/gpt-4o-mini");
        assert_eq!(endpoint.api_key.expose(), "sk-agent-7777");
        assert_eq!(
            endpoint.chat_completions_url(),
            format!("{GATEWAY_AGENT_ENDPOINT}/chat/completions")
        );
        assert!(matches!(
            load_agent(&pool, None).await,
            Err(ModelConfigError::KeyUnavailable)
        ));

        // Sharing: the agent takes the Jev key and drops its own.
        let share = agent_save(1, agent(true), None);
        assert_eq!(
            save_agent(&pool, Some(&sealer), share)
                .await
                .expect("share"),
            2
        );
        let agent_shared = read(&pool).await.expect("read").agent;
        assert!(agent_shared.spec.share_key_with_jev());
        assert_eq!(agent_shared.key_last4, None);
        let via_jev = load_agent(&pool, Some(&sealer))
            .await
            .expect("load")
            .expect("configured");
        assert_eq!(via_jev.api_key.expose(), "sk-console-abcd");

        // While shared, the agent cannot take a key of its own or leave the gateway, and
        // the Jev route and the revert cannot leave the gateway either.
        let own_key_while_shared = agent_save(2, agent(true), Some("sk-agent-1111"));
        assert_eq!(
            refusal(save_agent(&pool, Some(&sealer), own_key_while_shared).await),
            "MODEL_KEY_SHARE_INVALID"
        );
        let custom_agent = AgentSpec::new(
            AgentProvider::Custom,
            Some("https://agent.example.com/v1"),
            Some("gpt-4o-mini"),
            AGENT_TIMEOUT_MS,
            true,
        )
        .expect("a valid custom agent");
        assert_eq!(
            refusal(save_agent(&pool, Some(&sealer), agent_save(2, custom_agent, None)).await),
            "MODEL_KEY_SHARE_INVALID"
        );
        assert_eq!(
            refusal(
                save_jev(
                    &pool,
                    Some(&sealer),
                    jev_save(3, jev(JevRoute::Direct, JEV_TIMEOUT_MS), None)
                )
                .await
            ),
            "MODEL_KEY_SHARE_INVALID"
        );
        assert_eq!(
            refusal(revert_jev_to_env(&pool, 3, None).await),
            "MODEL_KEY_SHARE_INVALID"
        );

        // Unsharing gives the agent its own key again, and then the Jev route may change.
        let unshare = agent_save(2, agent(false), Some("sk-agent-8888"));
        assert_eq!(
            save_agent(&pool, Some(&sealer), unshare)
                .await
                .expect("unshare"),
            3
        );
        let own_secret = load_agent(&pool, Some(&sealer))
            .await
            .expect("load")
            .expect("configured");
        assert_eq!(own_secret.api_key.expose(), "sk-agent-8888");
        let route_change = jev_save(
            3,
            jev(JevRoute::Direct, JEV_TIMEOUT_MS),
            Some("sk-console-d1r3"),
        );
        assert_eq!(
            save_jev(&pool, Some(&sealer), route_change)
                .await
                .expect("route change"),
            4
        );

        // A stale revert is refused. The current version gives Jev back to the environment.
        assert_eq!(
            refusal(revert_jev_to_env(&pool, 3, Some("stale")).await),
            "VERSION_CONFLICT"
        );
        assert_eq!(
            revert_jev_to_env(&pool, 4, Some("back to environment"))
                .await
                .expect("revert"),
            5
        );
        let reverted = read(&pool).await.expect("read").jev;
        assert_eq!(reverted.version, 5);
        assert_eq!(reverted.key_last4, None);
        assert_eq!(reverted.spec.route(), JevRoute::Gateway);
        assert!(
            load_jev(&pool, Some(&sealer))
                .await
                .expect("load")
                .is_none()
        );
        let agent_after = load_agent(&pool, Some(&sealer))
            .await
            .expect("load")
            .expect("configured");
        assert_eq!(agent_after.api_key.expose(), "sk-agent-8888");

        // History lists the newest version first, and the key only as its last four characters.
        let newest_two = history(&pool, "jev", 2).await.expect("history");
        assert_eq!(versions(&newest_two), vec![5, 4]);
        let jev_history = history(&pool, "jev", 10).await.expect("history");
        assert_eq!(versions(&jev_history), vec![5, 4, 3, 2, 1]);
        let reverted_entry = &jev_history[0];
        assert_eq!(reverted_entry.change, "revert_to_env");
        assert_eq!(reverted_entry.key_change.as_deref(), Some("cleared"));
        assert_eq!(reverted_entry.note.as_deref(), Some("back to environment"));
        assert_eq!(reverted_entry.config["route"], "gateway");
        let rotated_entry = &jev_history[2];
        assert_eq!(rotated_entry.key_change.as_deref(), Some("replaced"));
        assert_eq!(rotated_entry.key_last4.as_deref(), Some("abcd"));
        assert!(rotated_entry.tested);
        let first_entry = &jev_history[4];
        assert_eq!(first_entry.change, "save");
        assert!(first_entry.tested);
        assert_eq!(first_entry.key_change.as_deref(), Some("replaced"));
        assert_eq!(first_entry.key_last4.as_deref(), Some("9f3a"));
        assert_eq!(first_entry.note.as_deref(), Some("first key"));
        assert_eq!(
            first_entry.changes,
            vec![HistoryChange {
                field: "key".to_owned(),
                from: String::new(),
                to: "9f3a".to_owned(),
            }]
        );
        let agent_history = history(&pool, "agent", 10).await.expect("history");
        assert_eq!(versions(&agent_history), vec![3, 2, 1]);
        assert_eq!(agent_history[0].key_last4.as_deref(), Some("8888"));
        let sharing_entry = &agent_history[1];
        assert_eq!(sharing_entry.key_change.as_deref(), Some("cleared"));
        assert_eq!(sharing_entry.key_last4, None);
        assert!(sharing_entry.changes.iter().any(|change| {
            change.field == "share_key_with_jev" && change.from == "false" && change.to == "true"
        }));
    }
}
