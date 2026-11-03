//! The object map of one site (console design section 7 and object-map design sections
//! 1 to 5): the positions the console lists, one position's drawer, the dismiss and
//! ambiguous actions, and the bootstrap candidates. It also lists the automatic changes,
//! takes their acknowledgements, and tells what a suspended position is judged by now.
//!
//! A learned position is addressed as `s<id>`, where the number is its row's identity. A
//! declared position, one the site's configuration names, is addressed as `a<digest>`,
//! where the digest is a prefix of the SHA-256 of its key, so its id stays the same while
//! its key does. The console treats both as opaque. The list shows each declared position
//! once, from the configuration, and absorbs the learned row for the same key.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use xshield_core::{
    context::{
        ObjectMap, ObjectSlot, SiteSpec, SlotSource,
        learning::{Evidence, RETIRE_DAYS, WINDOW_DAYS, day_of, observe},
    },
    kind::{NameReason, NameSource, Rules, request_name, response_name},
};
use xshield_postgres::{
    decision_stats::Scope,
    object_agent_store::{self as runs},
    object_learning_store::{self as store, Flow, JevFlow, PositionRow},
    site_spec_store::{self, SiteRecord},
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    object_agent_api::{self as agent_api, AgentBody, AgentPhase, AgentView, LearningRunBody},
    object_impact,
    params::{DAY_MILLIS, Params, now_millis, rfc3339},
    preview::ChangeBody,
};

/// The window the bootstrap candidates are read from, in hours.
const BOOTSTRAP_WINDOW_HOURS: i64 = 24;
/// Digits of a declared id's digest, lower case.
const HEX: &[u8; 16] = b"0123456789abcdef";
/// Bytes of a declared key's digest that its id keeps: 64 bits, far more than a site declares.
const DIGEST_BYTES: usize = 8;
/// Most flows a drawer lists for one position.
const FLOWS_MAX: usize = 20;
/// Most sample requests a drawer lists for one position.
const EXAMPLES_MAX: i64 = 3;
/// Days of automatic changes the object map lists.
const EVENTS_DAYS: i64 = 30;
/// Most automatic versions one object map response reads.
const EVENTS_MAX: i64 = 20;
/// Days the learning status line counts automatic changes over.
const STATUS_DAYS: i64 = 7;
/// Most learning runs the status line reads, to find the last one that finished.
const LAST_RUNS_READ: i64 = 5;
/// Who the console shows as the administrator that handled an automatic change: the store keeps
/// no name, since the console has one administrator.
const HANDLED_BY: &str = "administrator";
/// Milliseconds in an hour.
const HOUR_MILLIS: i64 = 3_600_000;
/// Most decision rows the bootstrap candidates read, the newest first.
const BOOTSTRAP_ROWS_MAX: i64 = 5_000;
/// Most candidates the bootstrap list returns.
const CANDIDATES_MAX: usize = 50;
/// A kind word this short may be an abbreviation, and its candidate asks for a look.
const SHORT_WORD: usize = 3;

/// The learning state of a position, as the console names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PositionState {
    Pending,
    Proposed,
    Confirmed,
    Ambiguous,
    Suspended,
    Retired,
}

impl PositionState {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Self::Pending,
            "proposed" => Self::Proposed,
            "confirmed" => Self::Confirmed,
            "ambiguous" => Self::Ambiguous,
            "suspended" => Self::Suspended,
            "retired" => Self::Retired,
            _ => return None,
        })
    }
}

/// Where a position sits: a value a request carries, or a response field a value was shown at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Side {
    Request,
    Response,
}

impl Side {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "request" => Some(Self::Request),
            "response" => Some(Self::Response),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }

    /// The side a flow reaches: a request position's flows end at response positions.
    fn opposite(self) -> Self {
        match self {
            Self::Request => Self::Response,
            Self::Response => Self::Request,
        }
    }
}

/// Where a kind or a position's kind came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Origin {
    Admin,
    Rule,
    Agent,
}

impl From<SlotSource> for Origin {
    fn from(source: SlotSource) -> Self {
        match source {
            SlotSource::Admin => Self::Admin,
            SlotSource::Rule => Self::Rule,
            SlotSource::Agent => Self::Agent,
        }
    }
}

/// One position as the console lists it: `ObjectSlotRow`, with the dismissal flag.
#[derive(Debug, Clone, Serialize)]
struct SlotRow {
    id: String,
    side: Side,
    key: String,
    class: Option<String>,
    state: PositionState,
    source: Origin,
    basis: String,
    last_seen: Option<String>,
    dismissed: bool,
    /// Whether the saved configuration uses the position's kind: a declared entry that is
    /// not paused. A learned position is never in effect, since the judge does not use it.
    in_effect: bool,
    /// The learning agent's status of a learned request position, when it has one.
    agent_status: Option<AgentPhase>,
    /// Why a suspended position is suspended, and what the rules would judge it by now. Only a
    /// suspended position has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    suspension: Option<SuspensionBody>,
}

/// Why a position is suspended, and what the rules judge it by now: `suspension`.
#[derive(Debug, Clone, Serialize)]
struct SuspensionBody {
    /// When the automatic pause happened. `None` when no pause of the last 30 days names the
    /// position, for example when the administrator has not set automatic pausing.
    at: Option<String>,
    /// Whether the learning task paused the position.
    auto: bool,
    version: Option<i64>,
    event_id: Option<String>,
    reason: Option<Value>,
    /// The entry the pause took away.
    previous: Option<PreviousBody>,
    /// What the rules judge the position by when its entry is not used, from its name.
    fallback: FallbackBody,
    /// The kinds the position's votes name since the pause, the largest share first.
    evidence_now: Vec<ShareBody>,
    /// Whether an administrator acknowledged the pause without changing the configuration.
    acknowledged: bool,
}

/// The entry an automatic pause took away: `suspension.previous`.
#[derive(Debug, Clone, Serialize)]
struct PreviousBody {
    class: Option<String>,
    source: Option<Origin>,
    /// When an administrator confirmed the entry. The configuration does not record it, so null.
    confirmed_at: Option<String>,
    /// Who confirmed the entry. The configuration does not record it, so null.
    confirmed_by: Option<String>,
}

/// The judgement a name gives a position: `suspension.fallback`.
#[derive(Debug, Clone, Serialize)]
struct FallbackBody {
    /// The declared kind the name relates to, or the kind word the name gives. Null when the name
    /// gives none.
    kind: Option<String>,
    /// The reason code of the name: `field_name`, `parent_name`, `endpoint_name` or `route_word`,
    /// or `none`.
    basis: &'static str,
    word: Option<String>,
}

/// The share of a position's votes that name one kind: `suspension.evidence_now`.
#[derive(Debug, Clone, Serialize)]
struct ShareBody {
    class: String,
    share: f64,
}

/// The learning pass's status line: `learning_status`.
#[derive(Debug, Serialize)]
struct LearningStatusBody {
    /// When the last learning run finished, when one has.
    last_pass_at: Option<String>,
    /// Automatic tightenings of the last seven days, counted per entry.
    auto_tighten_7d: usize,
    /// Automatic pauses of the last seven days, counted per entry.
    auto_pause_7d: usize,
}

/// The counts of the whole map: `ObjectCounts`. Retired positions are not counted.
#[derive(Debug, Serialize)]
struct Counts {
    classes: usize,
    pending: usize,
    proposed: usize,
    confirmed: usize,
    ambiguous: usize,
    suspended: usize,
}

/// One declared kind: `ObjectClass`.
#[derive(Debug, Serialize)]
struct ClassBody {
    id: String,
    name: String,
    description: String,
    origin: Origin,
    /// Sibling fields the kind is seen with. Not computed yet, so empty.
    fields: Vec<String>,
    slot_count: usize,
    /// Requests of the last 24 hours that used the kind. Not counted yet, so 0.
    uses_24h: u64,
    routes: Vec<String>,
}

/// `GET /objects`: `ObjectsResponse`.
#[derive(Debug, Serialize)]
pub(crate) struct ObjectsBody {
    counts: Counts,
    agent_configured: bool,
    /// Whether the model's last call gave an answer: `ok`, `failing`, or `unknown`.
    agent_health: &'static str,
    learning_run: LearningRunBody,
    classes: Vec<ClassBody>,
    slots: Vec<SlotRow>,
    /// Which automatic behaviours this build runs, so the console can say which are off.
    features: Features,
    /// The automatic changes of the last 30 days that no one has handled, newest first: one event
    /// per entry changed.
    events: Vec<AutomaticEvent>,
    /// The learning pass's status line.
    learning_status: LearningStatusBody,
}

/// `GET /objects/events`: the automatic changes the query names, newest first.
#[derive(Debug, Serialize)]
pub(crate) struct EventsBody {
    events: Vec<AutomaticEvent>,
}

/// How an administrator handled an automatic change: `status`. An event no one handled and no later
/// version changed is `open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EventState {
    Open,
    /// Known to the administrator, with the configuration unchanged.
    Acknowledged,
    /// Undone by a save, which named the event.
    Undone,
    /// A later version changed the same entry, so the event no longer describes it.
    Superseded,
}

/// Who handled an automatic change, and when: `handled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HandledBody {
    by: String,
    at: String,
    /// The version the handling saved, when it saved one.
    version: Option<i64>,
}

/// One side of an automatic change: the kind and the configuration entry it names. A pause that
/// removed the entry has no entry after it.
#[derive(Debug, Clone, Serialize)]
struct EntryBody {
    class: Option<String>,
    entry: Option<ObjectSlot>,
}

/// One automatic change to one entry: `ObjectEvent`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AutomaticEvent {
    id: String,
    kind: &'static str,
    at: String,
    version: i64,
    slot_id: String,
    key: String,
    side: Side,
    before: EntryBody,
    after: EntryBody,
    reason: Option<Value>,
    /// The fast allows the change turns back to Jev. Not counted yet, so empty.
    impact: Vec<Value>,
    /// Sample requests of the change. Not collected yet, so empty.
    examples: Vec<String>,
    status: EventState,
    handled: Option<HandledBody>,
    note: Option<String>,
    /// When the version was recorded, for the day window; not part of the response.
    #[serde(skip)]
    at_millis: i64,
}

/// The automatic behaviours this build runs: `features` of the object map's response.
#[derive(Debug, Serialize)]
pub(crate) struct Features {
    auto_tighten: bool,
    auto_pause: bool,
    path_confirm: bool,
}

/// What this build runs: the learning pass splits classes and pauses positions when the site's
/// learning settings ask for it, and the console confirms path positions.
const FEATURES: Features = Features {
    auto_tighten: true,
    auto_pause: true,
    path_confirm: true,
};

/// One other end of a position's flows: `ObjectFlow`.
#[derive(Debug, Serialize)]
struct FlowBody {
    key: String,
    side: Side,
    share: f64,
    uses: i64,
    sessions: i64,
    /// Requests that reached this end and that Jev allowed, from the decision log's Jev calls.
    jev_allow: i64,
    /// Requests that reached this end and that Jev refused, from the decision log's Jev calls.
    jev_deny: i64,
    method: String,
    route: String,
}

/// `GET /objects/slots/{id}`: `ObjectSlotDetail`. The shape and history are empty until their
/// sources are read.
#[derive(Debug, Serialize)]
pub(crate) struct SlotBody {
    #[serde(flatten)]
    row: SlotRow,
    flows_in: Vec<FlowBody>,
    /// The learning agent's share of the position, when it has one.
    agent: Option<AgentBody>,
    /// Request ids of the newest uses of the position, at most three.
    examples: Vec<String>,
    shape: Vec<Value>,
    history: Vec<Value>,
    /// The fast allows the position's main action moves over the last day: confirming a
    /// proposal, restoring a suspended entry, or pausing an entry in effect.
    impact: Vec<ChangeBody>,
    /// False when the impact was not read in full: the window held more decisions than it reads.
    impact_complete: bool,
    /// False when the action's impact is not estimated yet, which is a field position's: the impact
    /// does not read the field kinds. A position with no action has nothing to estimate.
    impact_estimated: bool,
}

/// `GET /objects/bootstrap`: `BootstrapResponse`.
#[derive(Debug, Serialize)]
pub(crate) struct BootstrapBody {
    window_hours: i64,
    /// The decision records the site logged in the window, so an empty list can be told
    /// apart from a site with no traffic.
    records: i64,
    candidates: Vec<Value>,
}

/// The agent filter of the list: the positions the agent is to answer, or whose answer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentFilter {
    Waiting,
    Failed,
}

/// The filters of the list: a state, a kind, a source, an agent status, and text the key or
/// the kind's id contains.
struct Filter {
    state: Option<PositionState>,
    class: Option<String>,
    source: Option<Origin>,
    agent: Option<AgentFilter>,
    text: Option<String>,
}

impl Filter {
    /// # Errors
    /// `INVALID_FILTER` naming the field whose value is not one the list takes: `state`,
    /// `source` (`admin`, `rule` or `agent`) or `agent` (`waiting` or `failed`).
    fn of(params: &Params) -> ApiResult<Self> {
        let state = params
            .text("state")
            .map(|value| {
                PositionState::parse(value).ok_or_else(|| ApiError::invalid_filter("state"))
            })
            .transpose()?;
        let source = params
            .text("source")
            .map(|value| match value {
                "admin" => Ok(Origin::Admin),
                "rule" => Ok(Origin::Rule),
                "agent" => Ok(Origin::Agent),
                _ => Err(ApiError::invalid_filter("source")),
            })
            .transpose()?;
        let agent = params
            .text("agent")
            .map(|value| match value {
                "waiting" => Ok(AgentFilter::Waiting),
                "failed" => Ok(AgentFilter::Failed),
                _ => Err(ApiError::invalid_filter("agent")),
            })
            .transpose()?;
        Ok(Self {
            state,
            class: params.text("class").map(str::to_owned),
            source,
            agent,
            text: params.text("q").map(str::to_ascii_lowercase),
        })
    }

    /// Whether a row is listed. Without a state filter the retired positions are left out.
    fn matches(&self, row: &SlotRow) -> bool {
        let state = match self.state {
            Some(state) => row.state == state,
            None => row.state != PositionState::Retired,
        };
        let class = self
            .class
            .as_deref()
            .is_none_or(|class| row.class.as_deref() == Some(class));
        let text = self.text.as_deref().is_none_or(|text| {
            row.key.to_ascii_lowercase().contains(text)
                || row
                    .class
                    .as_deref()
                    .is_some_and(|class| class.contains(text))
        });
        let source = self.source.is_none_or(|source| row.source == source);
        let agent = match self.agent {
            None => true,
            Some(AgentFilter::Waiting) => matches!(
                row.agent_status,
                Some(AgentPhase::Queued | AgentPhase::SkippedBudget)
            ),
            Some(AgentFilter::Failed) => row.agent_status == Some(AgentPhase::Failed),
        };
        state && class && source && agent && text
    }
}

/// `GET /api/sites/{name}/objects`: the counts of the whole map, the declared kinds, and the
/// positions the query matches. Retired positions are listed only with `state=retired`.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `INVALID_FILTER` naming `state` for a value that is
/// not a position state, and a 500 when a query fails.
pub async fn list(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<ObjectsBody>> {
    let filter = Filter::of(&Params::from(query))?;
    let record = site_of(&state, &name).await?;
    let now = now_millis();
    let learned = store::positions(&state.pool, &name).await?;
    let view = AgentView::load(&state, &record, now).await?;
    let mut rows = merged(&record.spec, &learned, &view)?;
    let events = automatic_events(&state, &record, now).await?;
    for row in &mut rows {
        row.suspension = suspension_of(&state, &record, &events, row, now).await?;
    }
    let waiting = rows
        .iter()
        .filter(|row| {
            matches!(
                row.agent_status,
                Some(AgentPhase::Queued | AgentPhase::SkippedBudget)
            )
        })
        .count();
    let failed = rows
        .iter()
        .filter(|row| row.agent_status == Some(AgentPhase::Failed))
        .count();
    let learning_run =
        agent_api::learning_run(&state.pool, &name, now, &view, waiting, failed).await?;
    let classes = record.spec.objects().classes().len();
    let learning_status = learning_status(&state, &record, &events, now).await?;
    Ok(Json(ObjectsBody {
        counts: counts_of(classes, &rows),
        agent_configured: view.model_configured(),
        agent_health: agent_api::health(&state.pool).await?,
        learning_run,
        classes: classes_of(&record.spec, &rows),
        slots: rows.into_iter().filter(|row| filter.matches(row)).collect(),
        features: FEATURES,
        events: events
            .into_iter()
            .filter(|event| event.status == EventState::Open)
            .collect(),
        learning_status,
    }))
}

/// `GET /api/sites/{name}/objects/slots/{id}`: one position with the flows of its values, the
/// Jev decisions on each flow, and the newest requests that used the position.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `SLOT_NOT_FOUND` (404) for an id that names no
/// position of the site, and a 500 when a query fails.
pub async fn slot(
    State(state): State<Arc<ControlState>>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<Json<SlotBody>> {
    let record = site_of(&state, &name).await?;
    let now = now_millis();
    let learned = store::positions(&state.pool, &name).await?;
    let view = AgentView::load(&state, &record, now).await?;
    let events = automatic_events(&state, &record, now).await?;
    let mut row = merged(&record.spec, &learned, &view)?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(slot_not_found)?;
    row.suspension = suspension_of(&state, &record, &events, &row, now).await?;
    let agent = match learned
        .iter()
        .find(|learned| learned_id(learned.id) == row.id)
    {
        Some(learned) => agent_api::agent_body(&state.pool, &name, &view, learned).await?,
        None => None,
    };
    let side = row.side;
    let oldest = oldest_day(now);
    let since = drawer_since(now, record.created_at.timestamp_millis());
    let total = store::uses(&state.pool, &name, &row.key, side.as_str(), oldest).await?;
    let flows = store::flows(&state.pool, &name, &row.key, side.as_str(), oldest).await?;
    let decisions = store::jev_flows(&state.pool, &name, &row.key, side.as_str(), since).await?;
    let examples = store::examples(
        &state.pool,
        &name,
        &row.key,
        side.as_str(),
        since,
        EXAMPLES_MAX,
    )
    .await?;
    let (impact, impact_complete) = slot_impact(&state, &record, &row, now).await?;
    let impact_estimated = action_is_estimated(&row);
    Ok(Json(SlotBody {
        row,
        flows_in: flow_bodies(side.opposite(), total, flows, &decisions),
        agent,
        examples,
        shape: Vec::new(),
        history: Vec::new(),
        impact,
        impact_complete,
        impact_estimated,
    }))
}

/// The impact a position's drawer shows: the fast allows its main action moves over the last
/// day, and whether that window was read in full. A path position's entry is written to the
/// object slots, so its action is judged here. A field position's kind is written to the field
/// kinds, which the impact does not read yet, so its action is not estimated.
///
/// # Errors
/// A 500 when the decisions cannot be read.
async fn slot_impact(
    state: &ControlState,
    record: &SiteRecord,
    row: &SlotRow,
    now: i64,
) -> ApiResult<(Vec<ChangeBody>, bool)> {
    let Some(action) = main_action(row) else {
        return Ok((Vec::new(), true));
    };
    if !is_path_key(&row.key) {
        return Ok((Vec::new(), false));
    }
    let current = &record.spec;
    let objects = objects_after(current.objects(), &row.key, &action);
    let proposed = current.clone().with_objects(objects);
    // The decision log outlives a site, so the rows from before this site was created belong to
    // a deleted site of the same name.
    let scope = Scope {
        site: Some(current.name().to_owned()),
        since_millis: (now - DAY_MILLIS).max(record.created_at.timestamp_millis()),
        until_millis: now,
    };
    object_impact::changes(&state.pool, &scope, current, &proposed).await
}

/// Whether the impact of a position's action is estimated. A field position's kind is not read by
/// the impact yet, so its action is not estimated. A position with no action has nothing to
/// estimate.
fn action_is_estimated(row: &SlotRow) -> bool {
    main_action(row).is_none() || is_path_key(&row.key)
}

/// What a position's main button does to the configuration, with the entry it writes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MainAction {
    /// Puts back the entry an automatic pause took away: the restore of a suspended position.
    Restore { class: String, source: SlotSource },
    /// Pauses the entry in effect, so the kind it gives is no longer used.
    Pause,
    /// Adds a learned proposal as an entry of its kind.
    Confirm { class: String, source: SlotSource },
}

/// The main action of a position's drawer, when it has one (console design 3.3 and 4.2). A
/// suspended position takes back the entry its pause took away, unless that entry is still in
/// effect: then the action pauses it. A proposal is confirmed as its kind.
fn main_action(row: &SlotRow) -> Option<MainAction> {
    match row.state {
        PositionState::Suspended if row.in_effect => Some(MainAction::Pause),
        PositionState::Suspended => {
            let previous = row.suspension.as_ref()?.previous.as_ref()?;
            Some(MainAction::Restore {
                class: previous.class.clone()?,
                source: slot_source(previous.source?),
            })
        }
        PositionState::Pending | PositionState::Proposed => Some(MainAction::Confirm {
            class: row.class.clone()?,
            source: slot_source(row.source),
        }),
        PositionState::Confirmed | PositionState::Ambiguous | PositionState::Retired => None,
    }
}

/// The object map once `action` is taken on the position `key`.
fn objects_after(objects: &ObjectMap, key: &str, action: &MainAction) -> ObjectMap {
    match action {
        MainAction::Pause => objects.clone().with_paused(&[key.to_owned()]),
        MainAction::Restore { class, source } | MainAction::Confirm { class, source } => {
            objects.clone().with_entry(key, class, *source)
        }
    }
}

/// Whether a position is a path parameter: its key ends in its segment, as
/// `GET /doctor/{id} path[1]` does. Any other key names a response field.
fn is_path_key(key: &str) -> bool {
    key.rsplit_once(' ')
        .is_some_and(|(_, location)| location.starts_with("path[") && location.ends_with(']'))
}

/// The configuration source an origin is written with.
fn slot_source(origin: Origin) -> SlotSource {
    match origin {
        Origin::Admin => SlotSource::Admin,
        Origin::Rule => SlotSource::Rule,
        Origin::Agent => SlotSource::Agent,
    }
}

/// `POST /api/sites/{name}/objects/slots/{id}/dismiss`: dismisses the proposal of a learned
/// request position, or the position while it is pending. The rules propose it again only
/// once its evidence has changed significantly.
///
/// # Errors
/// `SITE_NOT_FOUND` and `SLOT_NOT_FOUND` (404); `SLOT_IS_DECLARED` and `SLOT_NOT_REQUEST`
/// (409) for a position the action does not apply to; `SLOT_STATE_CONFLICT` (409) when the
/// position's state does not take a dismissal; a 500 when a write fails.
pub async fn dismiss(
    State(state): State<Arc<ControlState>>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let record = site_of(&state, &name).await?;
    let row = learned_request(&state, &name, &record.spec, &id).await?;
    let min_votes =
        i32::try_from(record.spec.objects().learning().thresholds.uses).unwrap_or(i32::MAX);
    let changed = store::dismiss(
        &state.pool,
        &name,
        record.created_at,
        row.id,
        min_votes,
        now_millis(),
    )
    .await?;
    changed_or_conflict(changed)
}

/// `POST /api/sites/{name}/objects/slots/{id}/ambiguous`: marks a learned request position
/// ambiguous. It stays with Jev, and the rules never propose it again.
///
/// # Errors
/// As [`dismiss`], with `SLOT_STATE_CONFLICT` for a confirmed position.
pub async fn ambiguous(
    State(state): State<Arc<ControlState>>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let record = site_of(&state, &name).await?;
    let row = learned_request(&state, &name, &record.spec, &id).await?;
    let changed =
        store::mark_ambiguous(&state.pool, &name, record.created_at, row.id, now_millis()).await?;
    changed_or_conflict(changed)
}

/// The filters of the events list: whether it lists the open events only, a kind, and the earliest
/// time an event may have.
struct EventFilter {
    open_only: bool,
    kind: Option<&'static str>,
    since_millis: i64,
}

impl EventFilter {
    /// # Errors
    /// `INVALID_FILTER` naming `status` (`open` or `all`), `kind` (`auto_tighten`, `auto_pause` or
    /// `anomaly`) or `days` (1 to [`EVENTS_DAYS`]) for a value the list does not take.
    fn of(params: &Params, now: i64) -> ApiResult<Self> {
        let open_only = match params.text("status") {
            None | Some("open") => true,
            Some("all") => false,
            Some(_) => return Err(ApiError::invalid_filter("status")),
        };
        let kind = match params.text("kind") {
            None => None,
            Some("auto_tighten") => Some("auto_tighten"),
            Some("auto_pause") => Some("auto_pause"),
            Some("anomaly") => Some("anomaly"),
            Some(_) => return Err(ApiError::invalid_filter("kind")),
        };
        let days = match params.int("days")? {
            None => EVENTS_DAYS,
            Some(days) if (1..=EVENTS_DAYS).contains(&days) => days,
            Some(_) => return Err(ApiError::invalid_filter("days")),
        };
        Ok(Self {
            open_only,
            kind,
            since_millis: now.saturating_sub(days.saturating_mul(DAY_MILLIS)),
        })
    }

    fn matches(&self, event: &AutomaticEvent) -> bool {
        (!self.open_only || event.status == EventState::Open)
            && self.kind.is_none_or(|kind| event.kind == kind)
            && event.at_millis >= self.since_millis
    }
}

/// `GET /api/sites/{name}/objects/events`: the automatic changes of the last `days` days, newest
/// first. `status=open` (the default) lists the ones no one has handled, and `status=all` lists them
/// all, with their handling.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, `INVALID_FILTER` naming `status`, `kind` or `days` for a
/// value the list does not take, and a 500 when a query fails.
pub async fn events(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
    Query(query): Query<BTreeMap<String, String>>,
) -> ApiResult<Json<EventsBody>> {
    let now = now_millis();
    let filter = EventFilter::of(&Params::from(query), now)?;
    let record = site_of(&state, &name).await?;
    let events = automatic_events(&state, &record, now).await?;
    Ok(Json(EventsBody {
        events: events
            .into_iter()
            .filter(|event| filter.matches(event))
            .collect(),
    }))
}

/// `POST /api/sites/{name}/objects/events/{id}/ack`: marks an automatic change as known, with the
/// configuration unchanged and no version written. Acknowledging an acknowledged change does nothing.
///
/// # Errors
/// `SITE_NOT_FOUND` and `EVENT_NOT_FOUND` (404) for an unknown site or event; `EVENT_UNDONE` and
/// `EVENT_SUPERSEDED` (409) for an event that is already undone, or that a later version changed.
pub async fn ack_event(
    State(state): State<Arc<ControlState>>,
    Path((name, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let record = site_of(&state, &name).await?;
    let now = now_millis();
    let event = find_event(&state, &record, &id, now).await?;
    match event.status {
        EventState::Acknowledged => Ok(StatusCode::NO_CONTENT),
        EventState::Open => {
            let handling = handling_of(&event, "acknowledged", None, now);
            store::record_event(&state.pool, &name, record.created_at, &handling).await?;
            Ok(StatusCode::NO_CONTENT)
        }
        EventState::Undone => Err(ApiError::new(StatusCode::CONFLICT, "EVENT_UNDONE")),
        EventState::Superseded => Err(ApiError::new(StatusCode::CONFLICT, "EVENT_SUPERSEDED")),
    }
}

/// An automatic change a save names as the change it undoes or re-confirms.
pub(crate) struct PendingEvent {
    site: String,
    generation: DateTime<Utc>,
    event: AutomaticEvent,
}

/// Checks, before a save writes, the automatic change the save names with `object_event`. The change
/// must still be open or acknowledged, so that the save undoes what the administrator sees.
///
/// # Errors
/// As [`ack_event`], for the change the save names.
pub(crate) async fn check_save_event(
    state: &ControlState,
    record: &SiteRecord,
    id: &str,
) -> ApiResult<PendingEvent> {
    let event = find_event(state, record, id, now_millis()).await?;
    match event.status {
        EventState::Open | EventState::Acknowledged => Ok(PendingEvent {
            site: record.spec.name().to_owned(),
            generation: record.created_at,
            event,
        }),
        EventState::Undone => Err(ApiError::new(StatusCode::CONFLICT, "EVENT_UNDONE")),
        EventState::Superseded => Err(ApiError::new(StatusCode::CONFLICT, "EVENT_SUPERSEDED")),
    }
}

/// Records, after a save wrote `version`, that the save undid the pending change. The position it
/// changed starts again from the day after the save: the evidence before that day stops counting for
/// it, and a suspended position is confirmed again. So the pass does not split or pause the position
/// again on the evidence that led to the change. The save has written the configuration already, so a
/// record that fails is logged, not returned.
pub(crate) async fn mark_saved(state: &ControlState, pending: &PendingEvent, version: i64) {
    let now = now_millis();
    let handling = handling_of(&pending.event, "undone", Some(version), now);
    if let Err(error) =
        store::record_event(&state.pool, &pending.site, pending.generation, &handling).await
    {
        eprintln!(
            "xshield-control: event {} not recorded as undone for site {}, {error}",
            pending.event.id, pending.site
        );
    }
    let baseline = day_of(u64::try_from(now).unwrap_or(0)).saturating_add(1);
    if let Err(error) = store::reconfirm(
        &state.pool,
        &pending.site,
        pending.generation,
        &pending.event.key,
        baseline,
        now,
    )
    .await
    {
        eprintln!(
            "xshield-control: position {} not re-confirmed for site {}, {error}",
            pending.event.key, pending.site
        );
    }
}

/// The suspension of a suspended position: the pause that suspended it, the entry it took away, what
/// the name gives, and the kinds its votes name since the pause. `None` for any other position.
///
/// # Errors
/// A 500 when a read of the evidence fails.
async fn suspension_of(
    state: &ControlState,
    record: &SiteRecord,
    events: &[AutomaticEvent],
    row: &SlotRow,
    now: i64,
) -> ApiResult<Option<SuspensionBody>> {
    if row.state != PositionState::Suspended {
        return Ok(None);
    }
    let map = record.spec.objects();
    let rules = Rules::of(record.spec.advanced());
    let pause = events
        .iter()
        .filter(|event| {
            event.kind == "auto_pause"
                && event.key == row.key
                && matches!(event.status, EventState::Open | EventState::Acknowledged)
        })
        .max_by_key(|event| event.version);
    let evidence = store::load_evidence(
        &state.pool,
        record.spec.name(),
        std::slice::from_ref(&row.key),
        oldest_day(now),
    )
    .await?;
    Ok(Some(SuspensionBody {
        at: pause.map(|event| event.at.clone()),
        auto: pause.is_some(),
        version: pause.map(|event| event.version),
        event_id: pause.map(|event| event.id.clone()),
        reason: pause.and_then(|event| event.reason.clone()),
        previous: pause.map(|event| PreviousBody {
            class: event.before.class.clone(),
            source: event
                .before
                .entry
                .as_ref()
                .map(|entry| Origin::from(entry.source)),
            confirmed_at: None,
            confirmed_by: None,
        }),
        fallback: fallback_of(&row.key, map, &rules),
        evidence_now: evidence
            .get(&row.key)
            .map_or_else(Vec::new, |votes| shares_of(votes, map)),
        acknowledged: pause.is_some_and(|event| event.status == EventState::Acknowledged),
    }))
}

/// What the rules judge a position by when its entry is not used: the declared kind its name relates
/// to, or the kind word the name gives, with the same name rules the judge reads.
fn fallback_of(key: &str, map: &ObjectMap, rules: &Rules) -> FallbackBody {
    let Some((reason, _)) = name_of(key, rules) else {
        return FallbackBody {
            kind: None,
            basis: "none",
            word: None,
        };
    };
    let kind = map
        .classes()
        .iter()
        .find(|class| rules.relates(&reason.word, &class.id))
        .map_or_else(|| reason.word.clone(), |class| class.id.clone());
    FallbackBody {
        kind: Some(kind),
        basis: reason_code(reason.source),
        word: Some(reason.word),
    }
}

/// The share of a position's votes each kind holds, the largest share first. Empty without votes.
fn shares_of(evidence: &Evidence, map: &ObjectMap) -> Vec<ShareBody> {
    let votes = evidence.votes();
    if votes == 0 {
        return Vec::new();
    }
    let mut shares: Vec<ShareBody> = evidence
        .kinds(map)
        .into_iter()
        .map(|(class, count)| ShareBody {
            class: class.to_owned(),
            share: f64::from(count) / f64::from(votes),
        })
        .collect();
    shares.sort_by(|left, right| {
        right
            .share
            .total_cmp(&left.share)
            .then_with(|| left.class.cmp(&right.class))
    });
    shares
}

/// The learning pass's status line: when it last finished, and how many automatic changes of each
/// kind the last seven days hold.
///
/// # Errors
/// A 500 when a read of the learning runs fails.
async fn learning_status(
    state: &ControlState,
    record: &SiteRecord,
    events: &[AutomaticEvent],
    now: i64,
) -> ApiResult<LearningStatusBody> {
    let last_pass_at = runs::recent_runs(&state.pool, record.spec.name(), LAST_RUNS_READ)
        .await?
        .iter()
        .find_map(|run| run.finished_millis)
        .and_then(rfc3339);
    let since = now.saturating_sub(STATUS_DAYS.saturating_mul(DAY_MILLIS));
    let recent = |kind: &str| {
        events
            .iter()
            .filter(|event| event.kind == kind && event.at_millis >= since)
            .count()
    };
    Ok(LearningStatusBody {
        last_pass_at,
        auto_tighten_7d: recent("auto_tighten"),
        auto_pause_7d: recent("auto_pause"),
    })
}

/// `GET /api/sites/{name}/objects/bootstrap`: the kinds the cold start can propose. The candidates
/// are the positions the site's own decision records used in the window, whose names give a kind and
/// which the configuration does not declare.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site, and a 500 when a read of the decision log fails.
pub async fn bootstrap(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<BootstrapBody>> {
    let record = site_of(&state, &name).await?;
    let since = now_millis().saturating_sub(BOOTSTRAP_WINDOW_HOURS.saturating_mul(HOUR_MILLIS));
    let records = store::records_since(&state.pool, &name, since).await?;
    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    for fact in store::recent_facts(&state.pool, &name, since, BOOTSTRAP_ROWS_MAX).await? {
        for vote in observe(&fact).votes {
            let session = vote.session;
            for key in std::iter::once(vote.slot).chain(vote.from) {
                tallies.entry(key).or_default().add(&session);
            }
        }
    }
    Ok(Json(BootstrapBody {
        window_hours: BOOTSTRAP_WINDOW_HOURS,
        records,
        candidates: candidates_of(&record.spec, &tallies),
    }))
}

/// The uses a position has in the window: the votes that name it, and the sessions among them.
#[derive(Debug, Default)]
struct Tally {
    uses: u32,
    sessions: BTreeSet<String>,
}

impl Tally {
    fn add(&mut self, session: &str) {
        self.uses += 1;
        self.sessions.insert(session.to_owned());
    }
}

/// The candidates of the tallies: each position the configuration does not declare and whose name
/// gives a kind, the most used first, at most [`CANDIDATES_MAX`].
fn candidates_of(spec: &SiteSpec, tallies: &BTreeMap<String, Tally>) -> Vec<Value> {
    let map = spec.objects();
    let rules = Rules::of(spec.advanced());
    let mut found: Vec<(u32, &str, Value)> = tallies
        .iter()
        .filter(|(key, _)| map.declared_class_of(key).is_none())
        .filter_map(|(key, tally)| {
            let (reason, side) = name_of(key, &rules)?;
            let class = map
                .classes()
                .iter()
                .find(|class| rules.relates(&reason.word, &class.id));
            let short = class.is_none() && reason.word.len() <= SHORT_WORD;
            let value = serde_json::json!({
                "id": digest_id('c', key),
                "key": key,
                "side": side,
                "kind": class.map_or(reason.word.as_str(), |class| class.id.as_str()),
                "name": class.map(|class| class.name.as_str()),
                "reason": {
                    "code": reason_code(reason.source),
                    "word": reason.word,
                    "field": reason.field,
                },
                "uses": tally.uses,
                "sessions": tally.sessions.len(),
                "note": short.then_some("名字较短，可能是缩写，请确认类别"),
                "conflict": null,
            });
            Some((tally.uses, key.as_str(), value))
        })
        .collect();
    found.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
    found
        .into_iter()
        .take(CANDIDATES_MAX)
        .map(|(_, _, value)| value)
        .collect()
}

/// The name a position's kind comes from, and the side of the position. `None` when the name gives
/// no kind, or the key is not a position this map reads.
fn name_of(key: &str, rules: &Rules) -> Option<(NameReason, &'static str)> {
    let mut parts = key.splitn(3, ' ');
    let (method, route, location) = (parts.next()?, parts.next()?, parts.next()?);
    match side_of_key(key) {
        Side::Request => {
            let reason = if let Some(index) = location
                .strip_prefix("path[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                request_name(route, None, index.parse().ok(), rules)?
            } else {
                let name = location
                    .strip_prefix("query.")
                    .or_else(|| location.strip_prefix("body."))?;
                request_name(route, Some(name), None, rules)?
            };
            Some((reason, Side::Request.as_str()))
        }
        Side::Response => {
            // A response field of an array is named by the field inside the array.
            let field = location.rsplit("[].").next().unwrap_or(location);
            let reason = response_name(field, &format!("{method} {route}"), rules)?;
            Some((reason, Side::Response.as_str()))
        }
    }
}

/// The kind word a position's name gives, when it gives one. The learning pass compares kinds
/// with it when it splits a class.
pub(crate) fn name_word(key: &str, rules: &Rules) -> Option<String> {
    name_of(key, rules).map(|(reason, _)| reason.word)
}

/// The reason code the console shows for a name's source.
fn reason_code(source: NameSource) -> &'static str {
    match source {
        NameSource::Field => "field_name",
        NameSource::Parent => "parent_name",
        NameSource::Endpoint => "endpoint_name",
        NameSource::Route => "route_word",
    }
}

/// The automatic changes of the last [`EVENTS_DAYS`] days, newest first: one event for each entry a
/// version changed, with the entry it replaced and the entry it became. An event's status is how an
/// administrator handled it, when that is recorded; otherwise it is `superseded` once the entry is no
/// longer the one the change made, and `open` while it is.
///
/// # Errors
/// A 500 when a read of the configuration history or of the handled events fails.
async fn automatic_events(
    state: &ControlState,
    record: &SiteRecord,
    now: i64,
) -> ApiResult<Vec<AutomaticEvent>> {
    let name = record.spec.name();
    let since = now.saturating_sub(EVENTS_DAYS.saturating_mul(DAY_MILLIS));
    let versions = site_spec_store::automatic_history(&state.pool, name, EVENTS_MAX).await?;
    let handled: BTreeMap<String, store::EventStatus> =
        store::event_statuses(&state.pool, name, record.created_at)
            .await?
            .into_iter()
            .map(|status| (status.event.clone(), status))
            .collect();
    let map = record.spec.objects();
    let mut events = Vec::new();
    for version in versions {
        if version.changed_at.timestamp_millis() < since {
            break;
        }
        let Some(spec) = version.spec.as_ref() else {
            continue;
        };
        let before = match version.version.checked_sub(1) {
            Some(earlier) if earlier > 0 => site_spec_store::version(&state.pool, name, earlier)
                .await?
                .and_then(|entry| entry.spec),
            _ => None,
        };
        for (index, (previous, slot)) in
            changed_slots(before.as_ref(), spec).into_iter().enumerate()
        {
            let id = format!("v{}-{index}", version.version);
            let current = map.slots().iter().find(|entry| entry.key == slot.key);
            events.push(automatic_event(
                &version,
                index,
                previous,
                slot,
                current,
                handled.get(&id),
            ));
        }
    }
    Ok(events)
}

/// One automatic change in the shape the console reads: the entry it replaced and the entry it
/// became, the side of the position, and the reason. A pause is for evidence that points at other
/// kinds. A tightening moves a position to the class its votes show, and its reason names the two
/// classes. The status is the administrator's handling when one is recorded. Otherwise it is
/// `superseded` when `current`, the entry the configuration holds now, is no longer the entry the
/// change made, and `open` when it is.
fn automatic_event(
    version: &site_spec_store::HistoryEntry,
    index: usize,
    previous: Option<&ObjectSlot>,
    slot: &ObjectSlot,
    current: Option<&ObjectSlot>,
    handled: Option<&store::EventStatus>,
) -> AutomaticEvent {
    let reason = match version.change {
        site_spec_store::Change::AutoPause => Some(serde_json::json!({ "code": "evidence_drift" })),
        site_spec_store::Change::AutoTighten => Some(serde_json::json!({
            "code": "split",
            "classes": [previous.map(|entry| entry.class.as_str()), slot.class.as_str()],
        })),
        _ => None,
    };
    let (status, handled) = match handled {
        Some(row) => (
            if row.status == "undone" {
                EventState::Undone
            } else {
                EventState::Acknowledged
            },
            Some(HandledBody {
                by: row.handled_by.clone(),
                at: rfc3339(row.handled_millis).unwrap_or_default(),
                version: row.handled_version,
            }),
        ),
        None if current == Some(slot) => (EventState::Open, None),
        None => (EventState::Superseded, None),
    };
    AutomaticEvent {
        id: format!("v{}-{index}", version.version),
        kind: version.change.as_str(),
        at: version.changed_at.to_rfc3339(),
        at_millis: version.changed_at.timestamp_millis(),
        version: version.version,
        slot_id: declared_id(&slot.key),
        key: slot.key.clone(),
        side: side_of_key(&slot.key),
        before: EntryBody {
            class: previous.map(|entry| entry.class.clone()),
            entry: previous.cloned(),
        },
        after: EntryBody {
            class: Some(slot.class.clone()),
            entry: Some(slot.clone()),
        },
        reason,
        impact: Vec::new(),
        examples: Vec::new(),
        status,
        handled,
        note: version.note.clone(),
    }
}

/// The automatic change with the given id among the automatic changes of the site.
///
/// # Errors
/// `EVENT_NOT_FOUND` (404) for an id that names no automatic change of the last [`EVENTS_DAYS`]
/// days, and a 500 when a read fails.
async fn find_event(
    state: &ControlState,
    record: &SiteRecord,
    id: &str,
    now: i64,
) -> ApiResult<AutomaticEvent> {
    automatic_events(state, record, now)
        .await?
        .into_iter()
        .find(|event| event.id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "EVENT_NOT_FOUND"))
}

/// The handling of an event as the store records it.
fn handling_of(
    event: &AutomaticEvent,
    status: &str,
    version: Option<i64>,
    now: i64,
) -> store::EventStatus {
    store::EventStatus {
        event: event.id.clone(),
        status: status.to_owned(),
        kind: event.kind.to_owned(),
        slot: event.key.clone(),
        handled_by: HANDLED_BY.to_owned(),
        handled_millis: now,
        handled_version: version,
    }
}

/// The entries of `after` that `before` does not hold as they are, each with the entry it replaced.
/// With no earlier configuration, every paused entry counts as changed.
fn changed_slots<'a>(
    before: Option<&'a SiteSpec>,
    after: &'a SiteSpec,
) -> Vec<(Option<&'a ObjectSlot>, &'a ObjectSlot)> {
    after
        .objects()
        .slots()
        .iter()
        .filter_map(|slot| {
            let previous = before.and_then(|spec| {
                spec.objects()
                    .slots()
                    .iter()
                    .find(|earlier| earlier.key == slot.key)
            });
            match (before, previous) {
                (Some(_), Some(earlier)) if earlier == slot => None,
                (Some(_), previous) => Some((previous, slot)),
                (None, _) => slot.paused.then_some((None, slot)),
            }
        })
        .collect()
}

/// The site's record: its configuration, and the generation the writes are checked against.
///
/// # Errors
/// `SITE_NOT_FOUND` when no such site exists.
pub(crate) async fn site_of(state: &ControlState, name: &str) -> ApiResult<SiteRecord> {
    site_spec_store::get(&state.pool, name)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"))
}

pub(crate) fn slot_not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "SLOT_NOT_FOUND")
}

/// The learned request position an action names. A declared position is decided by the
/// configuration, and a response position has no proposal, so both are refused.
///
/// # Errors
/// `SLOT_NOT_FOUND` (404) for an id that names no position of the site, `SLOT_IS_DECLARED`
/// and `SLOT_NOT_REQUEST` (409) for a position the action does not apply to, and a 500 when
/// a query fails.
pub(crate) async fn learned_request(
    state: &ControlState,
    name: &str,
    spec: &SiteSpec,
    id: &str,
) -> ApiResult<PositionRow> {
    if declared_of(spec, id).is_some() {
        return Err(ApiError::new(StatusCode::CONFLICT, "SLOT_IS_DECLARED"));
    }
    let row_id = learned_row_id(id).ok_or_else(slot_not_found)?;
    let row = store::position(&state.pool, name, row_id)
        .await?
        .ok_or_else(slot_not_found)?;
    if spec.objects().declared_class_of(&row.slot).is_some() {
        return Err(ApiError::new(StatusCode::CONFLICT, "SLOT_IS_DECLARED"));
    }
    if Side::parse(&row.side) != Some(Side::Request) {
        return Err(ApiError::new(StatusCode::CONFLICT, "SLOT_NOT_REQUEST"));
    }
    Ok(row)
}

/// `204` when the action changed the position, `409` when its state does not take the action.
fn changed_or_conflict(changed: bool) -> ApiResult<StatusCode> {
    if changed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(StatusCode::CONFLICT, "SLOT_STATE_CONFLICT"))
    }
}

/// Every position the site has: the declared ones first, in the order the configuration
/// gives them, then the learned ones that the configuration does not declare, in row order.
///
/// # Errors
/// `INTERNAL` when a stored state or side is not one this build reads.
fn merged(spec: &SiteSpec, learned: &[PositionRow], view: &AgentView) -> ApiResult<Vec<SlotRow>> {
    let objects = spec.objects();
    let by_key: BTreeMap<&str, &PositionRow> =
        learned.iter().map(|row| (row.slot.as_str(), row)).collect();
    let mut rows: Vec<SlotRow> = objects
        .slots()
        .iter()
        .map(|slot| declared_row(slot, by_key.get(slot.key.as_str()).copied()))
        .collect();
    for row in learned {
        if objects.declared_class_of(&row.slot).is_none() {
            rows.push(learned_row(row, view)?);
        }
    }
    Ok(rows)
}

/// A declared position: confirmed, or suspended when the learned row says its evidence now
/// points at other kinds. Its side comes from the learned row when there is one.
fn declared_row(slot: &ObjectSlot, learned: Option<&PositionRow>) -> SlotRow {
    let suspended = slot.paused || learned.is_some_and(|row| row.state == "suspended");
    let state = if suspended {
        PositionState::Suspended
    } else {
        PositionState::Confirmed
    };
    let side = learned
        .and_then(|row| Side::parse(&row.side))
        .unwrap_or_else(|| side_of_key(&slot.key));
    let basis = match learned {
        Some(row) if row.votes > 0 => evidence_basis(row),
        _ => "已在配置中声明".to_owned(),
    };
    SlotRow {
        id: declared_id(&slot.key),
        side,
        key: slot.key.clone(),
        class: Some(slot.class.clone()),
        state,
        source: Origin::from(slot.source),
        basis,
        last_seen: learned.and_then(|row| last_seen(row.last_day)),
        dismissed: false,
        in_effect: !slot.paused,
        agent_status: None,
        suspension: None,
    }
}

/// A learned position the configuration does not declare. Its basis names the agent's
/// confidence when the agent gave its kind, and says so when the agent and the rules
/// disagree.
///
/// # Errors
/// `INTERNAL` when the stored state, side or source is not one this build reads.
fn learned_row(row: &PositionRow, view: &AgentView) -> ApiResult<SlotRow> {
    let state = PositionState::parse(&row.state)
        .ok_or_else(|| ApiError::internal("object position state", &row.state))?;
    let side = Side::parse(&row.side)
        .ok_or_else(|| ApiError::internal("object position side", &row.side))?;
    let source = match row.source.as_str() {
        "agent" => Origin::Agent,
        "rule" => Origin::Rule,
        other => return Err(ApiError::internal("object position source", other)),
    };
    let answer = view.latest(&row.slot).filter(|call| call.choice.is_some());
    let basis = match state {
        PositionState::Retired => format!("超过 {RETIRE_DAYS} 天没有使用"),
        PositionState::Ambiguous if answer.is_some_and(|call| call.rule_choice.is_some()) => {
            "与规则不一致".to_owned()
        }
        PositionState::Ambiguous => "已标为不确定，不再提议".to_owned(),
        _ if row.dismissed && row.class.is_none() => "已忽略，证据明显变化后再提议".to_owned(),
        _ if source == Origin::Agent && row.class.is_some() => {
            match answer.and_then(|call| call.confidence) {
                Some(percent) => format!("学习代理 {percent}%"),
                None => "学习代理".to_owned(),
            }
        }
        _ if row.class.is_some() && row.votes > 0 => evidence_basis(row),
        _ => "学习中，尚无提议".to_owned(),
    };
    Ok(SlotRow {
        id: learned_id(row.id),
        side,
        key: row.slot.clone(),
        class: row.class.clone(),
        state,
        source,
        basis,
        last_seen: last_seen(row.last_day),
        dismissed: row.dismissed,
        in_effect: false,
        agent_status: view.phase_of(row),
        suspension: None,
    })
}

/// One line of evidence: the share of the position's uses that agree with its kind, the
/// sessions that made them, and the uses.
fn evidence_basis(row: &PositionRow) -> String {
    format!(
        "流向 {}% · {} 会话 · {} 次使用",
        row.share_per_mille / 10,
        row.sessions,
        row.votes
    )
}

/// The counts of the rows, with the retired ones left out.
fn counts_of(classes: usize, rows: &[SlotRow]) -> Counts {
    let mut counts = Counts {
        classes,
        pending: 0,
        proposed: 0,
        confirmed: 0,
        ambiguous: 0,
        suspended: 0,
    };
    for row in rows {
        match row.state {
            PositionState::Pending => counts.pending += 1,
            PositionState::Proposed => counts.proposed += 1,
            PositionState::Confirmed => counts.confirmed += 1,
            PositionState::Ambiguous => counts.ambiguous += 1,
            PositionState::Suspended => counts.suspended += 1,
            PositionState::Retired => {}
        }
    }
    counts
}

/// Each declared kind, with the positions it covers and the route templates they are used in.
fn classes_of(spec: &SiteSpec, rows: &[SlotRow]) -> Vec<ClassBody> {
    spec.objects()
        .classes()
        .iter()
        .map(|class| {
            let covered: Vec<&SlotRow> = rows
                .iter()
                .filter(|row| {
                    row.state != PositionState::Retired
                        && row.class.as_deref() == Some(class.id.as_str())
                })
                .collect();
            let routes: BTreeSet<&str> = covered
                .iter()
                .map(|row| route_of(&row.key))
                .filter(|route| !route.is_empty())
                .collect();
            ClassBody {
                id: class.id.clone(),
                name: class.name.clone(),
                description: class.description.clone(),
                origin: Origin::Admin,
                fields: Vec::new(),
                slot_count: covered.len(),
                uses_24h: 0,
                routes: routes.into_iter().map(str::to_owned).collect(),
            }
        })
        .collect()
}

/// One flow: the other end, the share of the position's uses that reach it, and the method
/// and route template at the other end.
fn flow_body(flow: Flow, side: Side, total: i64) -> FlowBody {
    FlowBody {
        method: method_of(&flow.other).to_owned(),
        route: route_of(&flow.other).to_owned(),
        share: share_of(flow.uses, total),
        key: flow.other,
        side,
        uses: flow.uses,
        sessions: flow.sessions,
        jev_allow: 0,
        jev_deny: 0,
    }
}

/// The other ends of a position's flows, each with Jev's decisions on its requests. The flows
/// the votes reached come first, most used first. An end the votes never reached follows them
/// with no uses, so a refusal alone is listed. Each group is capped at [`FLOWS_MAX`], so the
/// decisions on an end are never cut off by the flows that have uses.
fn flow_bodies(side: Side, total: i64, flows: Vec<Flow>, decisions: &[JevFlow]) -> Vec<FlowBody> {
    let mut by_end: BTreeMap<String, FlowBody> = flows
        .into_iter()
        .map(|flow| (flow.other.clone(), flow_body(flow, side, total)))
        .collect();
    let mut decided_alone = Vec::new();
    for decision in decisions {
        if let Some(body) = by_end.get_mut(&decision.other) {
            body.jev_allow = decision.allow;
            body.jev_deny = decision.deny;
        } else {
            let flow = Flow {
                other: decision.other.clone(),
                uses: 0,
                sessions: 0,
            };
            let mut body = flow_body(flow, side, total);
            body.jev_allow = decision.allow;
            body.jev_deny = decision.deny;
            decided_alone.push(body);
        }
    }
    let mut bodies: Vec<FlowBody> = by_end.into_values().collect();
    bodies.sort_by(|left, right| {
        right
            .uses
            .cmp(&left.uses)
            .then_with(|| left.key.cmp(&right.key))
    });
    bodies.truncate(FLOWS_MAX);
    decided_alone.sort_by(|left, right| {
        (right.jev_allow + right.jev_deny)
            .cmp(&(left.jev_allow + left.jev_deny))
            .then_with(|| left.key.cmp(&right.key))
    });
    decided_alone.truncate(FLOWS_MAX);
    bodies.extend(decided_alone);
    bodies
}

/// A flow's share of the position's uses, from 0 to 1.
#[allow(clippy::cast_precision_loss)] // Counts this size are exact in an f64.
fn share_of(uses: i64, total: i64) -> f64 {
    if total <= 0 {
        0.0
    } else {
        uses as f64 / total as f64
    }
}

/// The id of a learned position: `s` and its row's identity.
pub(crate) fn learned_id(id: i64) -> String {
    format!("s{id}")
}

/// The learned row an id names, when the id has the learned form.
pub(crate) fn learned_row_id(id: &str) -> Option<i64> {
    id.strip_prefix('s')?.parse().ok()
}

/// The id of a declared position: `a` and the leading bytes of the digest of its key.
fn declared_id(key: &str) -> String {
    digest_id('a', key)
}

/// An id made of `prefix` and the leading bytes of the digest of a position key, so that it stays
/// the same while the key does.
fn digest_id(prefix: char, key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut id = String::with_capacity(1 + 2 * DIGEST_BYTES);
    id.push(prefix);
    for byte in &digest[..DIGEST_BYTES] {
        id.push(char::from(HEX[usize::from(*byte >> 4)]));
        id.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    id
}

/// The declared position an id names, when the configuration declares one with that id.
fn declared_of<'a>(spec: &'a SiteSpec, id: &str) -> Option<&'a ObjectSlot> {
    spec.objects()
        .slots()
        .iter()
        .find(|slot| declared_id(&slot.key) == id)
}

/// The side a declared position sits on, read from its location: a request value sits at a
/// path segment, a query parameter or a body field, and any other location is a response
/// field. A learned row of the same key says the side it was seen on, and that wins.
fn side_of_key(key: &str) -> Side {
    let location = key.split(' ').nth(2).unwrap_or_default();
    if location.starts_with("path[")
        || location.starts_with("query.")
        || location.starts_with("body.")
    {
        Side::Request
    } else {
        Side::Response
    }
}

/// The method of a position key: `GET` in `GET /doctor/{id} path[1]`.
fn method_of(key: &str) -> &str {
    key.split(' ').next().unwrap_or_default()
}

/// The route template of a position key: `/doctor/{id}` in `GET /doctor/{id} path[1]`.
fn route_of(key: &str) -> &str {
    key.split(' ').nth(1).unwrap_or_default()
}

/// The start of a UTC day, the time a position's last day is shown as.
fn last_seen(last_day: i64) -> Option<String> {
    rfc3339(last_day.saturating_mul(DAY_MILLIS))
}

/// The first UTC day of the learning window at `now`, counted as the learning pass counts it.
pub(crate) fn oldest_day(now: i64) -> u64 {
    day_of(u64::try_from(now).unwrap_or(0)).saturating_sub(WINDOW_DAYS - 1)
}

/// The first millisecond of the learning window at `now`: the start of its first UTC day,
/// the lower bound of the decision rows the drawer reads.
fn window_start_millis(now: i64) -> i64 {
    i64::try_from(oldest_day(now))
        .unwrap_or(0)
        .saturating_mul(DAY_MILLIS)
}

/// The first millisecond of the decision rows the drawer reads: the start of the learning
/// window, or the site's creation when that is later. The decision log outlives a site, so a
/// site created again under the same name must not show the rows of the one before it.
fn drawer_since(now: i64, created_millis: i64) -> i64 {
    window_start_millis(now).max(created_millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SiteSpec {
        SiteSpec::from_json(
            r#"{
                "name": "clinic",
                "hosts": ["clinic.example.com"],
                "origin": "http://10.0.0.5:8080",
                "session": {"cookie": "SESSIONID"},
                "entries": ["/login"],
                "objects": {
                    "classes": [{"id": "doctor", "name": "医生", "description": "值班医生"}],
                    "slots": [
                        {"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "admin"},
                        {"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "rule"}
                    ]
                }
            }"#,
        )
        .expect("the test spec")
    }

    fn row(id: i64, slot: &str, side: &str, state: &str, class: Option<&str>) -> PositionRow {
        PositionRow {
            id,
            slot: slot.to_owned(),
            side: side.to_owned(),
            state: state.to_owned(),
            class: class.map(str::to_owned),
            dismissed: false,
            source: "rule".to_owned(),
            votes: 0,
            sessions: 0,
            share_per_mille: 0,
            last_day: 3,
        }
    }

    #[test]
    fn a_declared_id_is_stable_and_differs_between_keys() {
        let first = declared_id("GET /doctor/{id} path[1]");
        assert_eq!(first, declared_id("GET /doctor/{id} path[1]"));
        assert_ne!(first, declared_id("GET /doctor/{id} path[2]"));
        assert_eq!(first.len(), 1 + 2 * DIGEST_BYTES);
        assert!(first.starts_with('a'));
        assert!(
            first[1..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    #[test]
    fn a_learned_id_names_its_row_and_no_other() {
        assert_eq!(learned_row_id(&learned_id(42)), Some(42));
        assert_eq!(learned_row_id("s"), None);
        assert_eq!(learned_row_id("x42"), None);
        assert_eq!(
            learned_row_id(&declared_id("GET /doctor/{id} path[1]")),
            None
        );
    }

    #[test]
    fn the_side_of_a_position_follows_its_location() {
        assert_eq!(side_of_key("GET /doctor/{id} path[1]"), Side::Request);
        assert_eq!(side_of_key("GET /api/search query.by"), Side::Request);
        assert_eq!(side_of_key("POST /api/notes body.note.text"), Side::Request);
        assert_eq!(
            side_of_key("GET /api/appointments [].doc_id"),
            Side::Response
        );
        assert_eq!(side_of_key("GET /api/me name"), Side::Response);
    }

    #[test]
    fn the_method_and_route_of_a_key_are_its_first_two_words() {
        assert_eq!(method_of("GET /doctor/{id} path[1]"), "GET");
        assert_eq!(route_of("GET /doctor/{id} path[1]"), "/doctor/{id}");
        assert_eq!(route_of("GET"), "");
    }

    #[test]
    fn a_declared_position_is_listed_once_from_the_configuration() {
        let learned = [
            // Seen as a response field of the appointments route, and not judged.
            row(
                1,
                "GET /api/appointments [].doc_id",
                "response",
                "pending",
                None,
            ),
            // The doctor position's evidence now points elsewhere.
            row(
                2,
                "GET /doctor/{id} path[1]",
                "request",
                "suspended",
                Some("doctor"),
            ),
            // A position the configuration does not declare, proposed by the rules.
            row(
                3,
                "GET /other/{id} path[1]",
                "request",
                "proposed",
                Some("doctor"),
            ),
        ];
        let rows = merged(&spec(), &learned, &AgentView::idle()).unwrap();
        assert_eq!(rows.len(), 3);
        let appointments = &rows[0];
        assert_eq!(appointments.key, "GET /api/appointments [].doc_id");
        assert_eq!(appointments.side, Side::Response);
        assert_eq!(appointments.state, PositionState::Confirmed);
        assert_eq!(appointments.source, Origin::Admin);
        assert_eq!(appointments.id, declared_id(&appointments.key));
        let doctor = &rows[1];
        assert_eq!(doctor.state, PositionState::Suspended);
        assert_eq!(doctor.source, Origin::Rule);
        assert_eq!(doctor.side, Side::Request);
        let other = &rows[2];
        assert_eq!(other.id, "s3");
        assert_eq!(other.state, PositionState::Proposed);
        assert_eq!(other.source, Origin::Rule);
    }

    #[test]
    fn a_learned_row_in_an_unknown_state_is_an_internal_error() {
        let error = learned_row(
            &row(1, "GET /x path[1]", "request", "bogus", None),
            &AgentView::idle(),
        )
        .unwrap_err();
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn counts_leave_retired_positions_out_and_filters_match_their_fields() {
        let learned = [
            row(1, "GET /other/{id} path[1]", "request", "pending", None),
            row(2, "GET /old/{id} path[1]", "request", "retired", None),
        ];
        let rows = merged(&spec(), &learned, &AgentView::idle()).unwrap();
        let counts = counts_of(1, &rows);
        assert_eq!(
            (
                counts.classes,
                counts.pending,
                counts.confirmed,
                counts.proposed
            ),
            // Both declared positions are confirmed; the unlisted retired row is not counted.
            (1, 1, 2, 0)
        );
        let listed = |params: &[(&str, &str)]| {
            let filter = Filter::of(&Params::from(
                params
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect::<BTreeMap<_, _>>(),
            ))
            .unwrap();
            rows.iter()
                .filter(|row| filter.matches(row))
                .map(|row| row.id.clone())
                .collect::<Vec<_>>()
        };
        // The default list has no retired position; the state filter lists it.
        assert_eq!(listed(&[]).len(), 3);
        assert_eq!(listed(&[("state", "retired")]), vec!["s2".to_owned()]);
        assert_eq!(listed(&[("class", "doctor")]).len(), 2);
        assert_eq!(listed(&[("q", "/DOCTOR/")]).len(), 1);
        assert!(listed(&[("class", "document")]).is_empty());
    }

    #[test]
    fn a_state_filter_names_a_position_state_or_is_refused() {
        let params = Params::from(BTreeMap::from([(
            "state".to_owned(),
            "dismissed".to_owned(),
        )]));
        let error = Filter::of(&params)
            .err()
            .expect("an unknown state is refused");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_evidence_line_shows_the_share_the_sessions_and_the_uses() {
        let mut evidence = row(1, "GET /x path[1]", "request", "proposed", Some("doctor"));
        evidence.share_per_mille = 870;
        evidence.sessions = 23;
        evidence.votes = 40;
        assert_eq!(evidence_basis(&evidence), "流向 87% · 23 会话 · 40 次使用");
    }

    #[test]
    fn a_share_is_the_flow_uses_over_the_position_uses() {
        assert!((share_of(1, 4) - 0.25).abs() < f64::EPSILON);
        assert!(share_of(3, 0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_flow_takes_the_jev_decisions_on_its_end_and_a_refusal_alone_is_listed() {
        let flows = vec![
            Flow {
                other: "GET /api/appointments [].doc_id".to_owned(),
                uses: 140,
                sessions: 23,
            },
            Flow {
                other: "GET /api/schedule query.doc".to_owned(),
                uses: 18,
                sessions: 6,
            },
        ];
        let decisions = [
            JevFlow {
                other: "GET /api/appointments [].doc_id".to_owned(),
                allow: 140,
                deny: 0,
            },
            JevFlow {
                other: "GET /api/records/{id} attachments[].doc_id".to_owned(),
                allow: 0,
                deny: 3,
            },
        ];
        let bodies = flow_bodies(Side::Response, 158, flows, &decisions);
        let keys: Vec<&str> = bodies.iter().map(|body| body.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "GET /api/appointments [].doc_id",
                "GET /api/schedule query.doc",
                // No votes reached it, so it has no uses and no share, and follows the flows.
                "GET /api/records/{id} attachments[].doc_id",
            ]
        );
        assert_eq!((bodies[0].jev_allow, bodies[0].jev_deny), (140, 0));
        assert_eq!((bodies[1].jev_allow, bodies[1].jev_deny), (0, 0));
        assert_eq!((bodies[2].uses, bodies[2].jev_deny), (0, 3));
        assert!(bodies[2].share.abs() < f64::EPSILON);
        assert_eq!(bodies[2].method, "GET");
        assert_eq!(bodies[2].route, "/api/records/{id}");
    }

    #[test]
    fn a_refusal_on_an_end_no_vote_reached_is_listed_past_a_full_list_of_flows() {
        let flows: Vec<Flow> = (0..FLOWS_MAX)
            .map(|index| Flow {
                other: format!("GET /api/votes/{index} query.doc"),
                uses: 1,
                sessions: 1,
            })
            .collect();
        // Twenty-five ends with refusals and no votes: the first refused once, the last 25 times.
        let refused: Vec<JevFlow> = (1..=25_i64)
            .map(|deny| JevFlow {
                other: format!("GET /api/refused/{deny} query.doc"),
                allow: 0,
                deny,
            })
            .collect();
        let bodies = flow_bodies(Side::Response, 20, flows, &refused);
        // Each group is capped at twenty: the flows with votes, then the refusals with the most.
        assert_eq!(bodies.len(), 2 * FLOWS_MAX);
        assert!(bodies[..FLOWS_MAX].iter().all(|body| body.uses == 1));
        assert_eq!(
            (bodies[FLOWS_MAX].uses, bodies[FLOWS_MAX].jev_deny),
            (0, 25)
        );
        assert_eq!(bodies[2 * FLOWS_MAX - 1].jev_deny, 6);
    }

    #[test]
    fn the_drawer_reads_no_decision_from_before_the_site_was_created() {
        // The learning window of day 100 starts on day 94.
        let now = 100 * DAY_MILLIS + 5_000;
        let window_start = 94 * DAY_MILLIS;
        // A site created before the window reads all of it. One created inside it reads only
        // from its creation on.
        assert_eq!(drawer_since(now, 10 * DAY_MILLIS), window_start);
        assert_eq!(drawer_since(now, 96 * DAY_MILLIS + 1), 96 * DAY_MILLIS + 1);
    }

    #[test]
    fn the_learning_window_starts_at_the_first_millisecond_of_its_first_day() {
        let now = 10 * DAY_MILLIS + 5 * 60_000;
        let window = i64::try_from(WINDOW_DAYS).expect("a small window");
        assert_eq!(window_start_millis(now), (10 - (window - 1)) * DAY_MILLIS);
    }

    /// A site declaring the given entries, for the entries an automatic change touched.
    fn site_with_slots(slots: &str) -> SiteSpec {
        let text = format!(
            r#"{{"name": "clinic", "hosts": ["clinic.example.com"], "origin": "http://10.0.0.5:8080",
                "session": {{"cookie": "SESSIONID"}}, "entries": ["/login"],
                "objects": {{"classes": [{{"id": "doctor", "name": "医生"}}], "slots": [{slots}]}}}}"#
        );
        SiteSpec::from_json(&text).expect("test spec")
    }

    #[test]
    fn bootstrap_candidates_name_the_positions_the_site_uses_and_does_not_declare() {
        let spec = site_with_slots(
            r#"{"key": "GET /api/notes [].author_id", "class": "doctor", "source": "admin"}"#,
        );
        let tally = |sessions: &[&str]| {
            let mut tally = Tally::default();
            for session in sessions {
                tally.add(session);
            }
            tally
        };
        let tallies = BTreeMap::from([
            ("GET /doctor/{id} path[1]".to_owned(), tally(&["a", "b"])),
            ("GET /api/doctors [].id".to_owned(), tally(&["a", "b", "c"])),
            ("GET /api/docs [].id".to_owned(), tally(&["a"])),
            ("GET /api/notes [].author_id".to_owned(), tally(&["a"])),
            ("GET /api/me [].name".to_owned(), tally(&["a"])),
        ]);
        let candidates = candidates_of(&spec, &tallies);
        // The declared position and the field that names no kind are left out. The most used
        // comes first.
        assert_eq!(candidates.len(), 3);
        let first = &candidates[0];
        assert_eq!(first["key"], "GET /api/doctors [].id");
        assert_eq!(first["side"], "response");
        assert_eq!(first["kind"], "doctor");
        assert_eq!(first["name"], "医生");
        assert_eq!(first["reason"]["code"], "endpoint_name");
        assert_eq!(first["reason"]["word"], "doctor");
        assert_eq!(
            (first["uses"].as_u64(), first["sessions"].as_u64()),
            (Some(3), Some(3))
        );
        assert!(first["note"].is_null());
        assert!(first["id"].as_str().is_some_and(|id| id.starts_with('c')));
        let second = &candidates[1];
        assert_eq!(second["key"], "GET /doctor/{id} path[1]");
        assert_eq!(second["side"], "request");
        assert_eq!(second["reason"]["code"], "route_word");
        assert_eq!(second["kind"], "doctor");
        // An abbreviation has no class of the site yet, so its candidate asks for a look.
        let third = &candidates[2];
        assert_eq!(
            (third["kind"].as_str(), third["name"].is_null()),
            (Some("doc"), true)
        );
        assert!(third["note"].is_string());
    }

    #[test]
    fn an_automatic_pause_event_names_its_entries_its_side_and_its_reason() {
        let entry = r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "rule"}"#;
        let before = site_with_slots(entry);
        let paused = site_with_slots(&entry.replace("\"rule\"", "\"rule\", \"paused\": true"));
        let version = site_spec_store::HistoryEntry {
            version: 3,
            change: site_spec_store::Change::AutoPause,
            rollback_of: None,
            note: Some("学习任务自动暂停了 1 个位置".to_owned()),
            changed_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).expect("the epoch"),
            spec: Some(paused.clone()),
        };
        let event = serde_json::to_value(automatic_event(
            &version,
            0,
            Some(&before.objects().slots()[0]),
            &paused.objects().slots()[0],
            Some(&paused.objects().slots()[0]),
            None,
        ))
        .expect("an event");
        assert_eq!(event["id"], "v3-0");
        assert_eq!(event["kind"], "auto_pause");
        assert_eq!(event["status"], "open");
        assert_eq!(event["side"], "request");
        assert_eq!(event["before"]["class"], "doctor");
        // An unpaused entry has no `paused` key, and the paused one says so.
        assert_eq!(event["before"]["entry"]["paused"], Value::Null);
        assert_eq!(event["after"]["entry"]["paused"], true);
        assert_eq!(event["reason"]["code"], "evidence_drift");
    }

    #[test]
    fn an_automatic_tightening_names_the_two_classes_it_moved_between() {
        let spec = |class: &str| {
            let text = format!(
                r#"{{"name": "clinic", "hosts": ["clinic.example.com"], "origin": "http://10.0.0.5:8080",
                    "session": {{"cookie": "SESSIONID"}}, "entries": ["/login"],
                    "objects": {{"classes": [{{"id": "doctor", "name": "医生"}}, {{"id": "documents", "name": "文档"}}],
                    "slots": [{{"key": "GET /doctor/{{id}} path[1]", "class": "{class}", "source": "rule"}}]}}}}"#
            );
            SiteSpec::from_json(&text).expect("test spec")
        };
        let before = spec("doctor");
        let moved = spec("documents");
        let version = site_spec_store::HistoryEntry {
            version: 4,
            change: site_spec_store::Change::AutoTighten,
            rollback_of: None,
            note: Some("学习任务自动收紧了 1 个位置".to_owned()),
            changed_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).expect("the epoch"),
            spec: Some(moved.clone()),
        };
        let event = serde_json::to_value(automatic_event(
            &version,
            0,
            Some(&before.objects().slots()[0]),
            &moved.objects().slots()[0],
            Some(&moved.objects().slots()[0]),
            None,
        ))
        .expect("an event");
        assert_eq!(event["kind"], "auto_tighten");
        assert_eq!(event["status"], "open");
        assert_eq!(event["before"]["class"], "doctor");
        assert_eq!(event["after"]["class"], "documents");
        assert_eq!(event["reason"]["code"], "split");
        assert_eq!(
            event["reason"]["classes"],
            serde_json::json!(["doctor", "documents"])
        );
    }

    #[test]
    fn an_automatic_pause_shows_the_entry_it_paused_and_the_entry_before_it() {
        let entry = r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "rule"}"#;
        let before = site_with_slots(entry);
        let paused = site_with_slots(&entry.replace("\"rule\"", "\"rule\", \"paused\": true"));
        let changed = changed_slots(Some(&before), &paused);
        assert_eq!(changed.len(), 1);
        let (previous, slot) = changed[0];
        assert_eq!(previous.map(|entry| entry.paused), Some(false));
        assert!(slot.paused);
        // The same configuration changes nothing, and a version with no earlier one shows its pauses.
        assert!(changed_slots(Some(&paused), &paused).is_empty());
        assert_eq!(changed_slots(None, &paused).len(), 1);
        assert!(changed_slots(None, &before).is_empty());
    }

    /// A version of `spec`, recorded at `millis` after the epoch.
    fn version_at(
        spec: &SiteSpec,
        change: site_spec_store::Change,
        version: i64,
        millis: i64,
    ) -> site_spec_store::HistoryEntry {
        site_spec_store::HistoryEntry {
            version,
            change,
            rollback_of: None,
            note: None,
            changed_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)
                .expect("a time"),
            spec: Some(spec.clone()),
        }
    }

    /// How an administrator handled the pause `v3-0` of the request position of the doctor route.
    fn handled(status: &str, version: Option<i64>) -> store::EventStatus {
        store::EventStatus {
            event: "v3-0".to_owned(),
            status: status.to_owned(),
            kind: "auto_pause".to_owned(),
            slot: "GET /doctor/{id} path[1]".to_owned(),
            handled_by: HANDLED_BY.to_owned(),
            handled_millis: 1_000,
            handled_version: version,
        }
    }

    #[test]
    fn an_event_is_superseded_once_a_later_version_changed_its_entry() {
        let entry = r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "rule"}"#;
        let before = site_with_slots(entry);
        let paused = site_with_slots(&entry.replace("\"rule\"", "\"rule\", \"paused\": true"));
        let version = version_at(&paused, site_spec_store::Change::AutoPause, 3, 0);
        let status = |current: &SiteSpec, handling: Option<&store::EventStatus>| {
            automatic_event(
                &version,
                0,
                Some(&before.objects().slots()[0]),
                &paused.objects().slots()[0],
                current.objects().slots().first(),
                handling,
            )
            .status
        };
        // The entry is still the paused one, so the event is open; a later version that put the
        // unpaused entry back supersedes it.
        assert_eq!(status(&paused, None), EventState::Open);
        assert_eq!(status(&before, None), EventState::Superseded);
        // A handling stands even when a later version changed the entry again.
        assert_eq!(
            status(&before, Some(&handled("undone", Some(4)))),
            EventState::Undone
        );
        assert_eq!(
            status(&before, Some(&handled("acknowledged", None))),
            EventState::Acknowledged
        );
    }

    #[test]
    fn a_handling_names_who_made_it_and_the_version_it_saved() {
        let entry = r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "rule", "paused": true}"#;
        let paused = site_with_slots(entry);
        let version = version_at(&paused, site_spec_store::Change::AutoPause, 3, 0);
        let event = |handling: Option<&store::EventStatus>| {
            serde_json::to_value(automatic_event(
                &version,
                0,
                None,
                &paused.objects().slots()[0],
                Some(&paused.objects().slots()[0]),
                handling,
            ))
            .expect("an event")
        };
        let undone = event(Some(&handled("undone", Some(4))));
        assert_eq!(undone["status"], "undone");
        assert_eq!(undone["handled"]["by"], "administrator");
        assert_eq!(undone["handled"]["version"], 4);
        let acknowledged = event(Some(&handled("acknowledged", None)));
        assert_eq!(acknowledged["status"], "acknowledged");
        assert_eq!(acknowledged["handled"]["version"], Value::Null);
        assert_eq!(event(None)["handled"], Value::Null);
    }

    #[test]
    fn the_events_list_takes_the_status_kind_and_days_it_names_and_refuses_the_rest() {
        let now = 40 * DAY_MILLIS;
        let filter = |query: &[(&str, &str)]| {
            let map: BTreeMap<String, String> = query
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect();
            EventFilter::of(&Params::from(map), now)
        };
        assert!(filter(&[]).expect("the default").open_only);
        assert!(!filter(&[("status", "all")]).expect("all").open_only);
        assert_eq!(
            filter(&[("days", "2")]).expect("two days").since_millis,
            now - 2 * DAY_MILLIS
        );
        for (query, field) in [
            (&[("status", "some")][..], "status"),
            (&[("kind", "other")][..], "kind"),
            (&[("days", "31")][..], "days"),
            (&[("days", "0")][..], "days"),
        ] {
            let error = filter(query).err().expect("a refused filter");
            assert_eq!(error.code(), "INVALID_FILTER", "{field}");
        }
        // An event of 35 days ago is listed by the 30-day default and not by a two-day list.
        let old = version_at(
            &spec_with_one_pause(),
            site_spec_store::Change::AutoPause,
            3,
            now - 35 * DAY_MILLIS,
        );
        let event = automatic_event(
            &old,
            0,
            None,
            &old.spec.as_ref().expect("a spec").objects().slots()[0],
            None,
            None,
        );
        assert!(!filter(&[]).expect("default").matches(&event));
        assert!(!filter(&[("days", "30")]).expect("thirty").matches(&event));
        assert!(!filter(&[("days", "2")]).expect("two").matches(&event));
    }

    /// A spec whose one position is paused, as the pause wrote it.
    fn spec_with_one_pause() -> SiteSpec {
        site_with_slots(
            r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "rule", "paused": true}"#,
        )
    }

    #[test]
    fn a_suspension_falls_back_to_the_kind_its_name_gives_and_names_the_kinds_its_votes_show() {
        let spec = SiteSpec::from_json(
            r#"{"name": "clinic", "hosts": ["clinic.example.com"], "origin": "http://10.0.0.5:8080",
                "session": {"cookie": "SESSIONID"}, "entries": ["/login"],
                "objects": {"classes": [{"id": "doctor", "name": "医生"}, {"id": "documents", "name": "文档"}],
                "slots": [{"key": "GET /api/records/{id} attachments[].doc_id", "class": "documents", "source": "admin"},
                          {"key": "GET /api/records/{id} doctor.id", "class": "doctor", "source": "admin"}]}}"#,
        )
        .expect("test spec");
        let rules = Rules::of(spec.advanced());
        let fallback = fallback_of("GET /doctor/{id} path[1]", spec.objects(), &rules);
        assert_eq!(fallback.kind.as_deref(), Some("doctor"));
        assert_eq!(fallback.basis, "route_word");
        assert_eq!(fallback.word.as_deref(), Some("doctor"));
        let none = fallback_of("GET /x path[1]", spec.objects(), &rules);
        assert_eq!((none.kind, none.basis, none.word), (None, "none", None));

        let mut votes = Evidence::default();
        for (session, from) in [
            ("s1", "GET /api/records/{id} attachments[].doc_id"),
            ("s2", "GET /api/records/{id} attachments[].doc_id"),
            ("s3", "GET /api/records/{id} doctor.id"),
        ] {
            votes.add_vote(xshield_core::context::learning::Vote {
                slot: "GET /doctor/{id} path[1]".to_owned(),
                session: session.to_owned(),
                day: 1,
                from: vec![from.to_owned()],
            });
        }
        let shares = shares_of(&votes, spec.objects());
        assert_eq!(
            shares
                .iter()
                .map(|share| share.class.as_str())
                .collect::<Vec<_>>(),
            ["documents", "doctor"]
        );
        assert!((shares[0].share - 2.0 / 3.0).abs() < 1e-9);
        assert!(shares_of(&Evidence::default(), spec.objects()).is_empty());
    }

    /// A position of `key` with no suspension: the parts a main action reads.
    fn slot_row(
        key: &str,
        state: PositionState,
        source: Origin,
        class: Option<&str>,
        in_effect: bool,
    ) -> SlotRow {
        SlotRow {
            id: String::new(),
            side: Side::Request,
            key: key.to_owned(),
            class: class.map(str::to_owned),
            state,
            source,
            basis: String::new(),
            last_seen: None,
            dismissed: false,
            in_effect,
            agent_status: None,
            suspension: None,
        }
    }

    /// The suspension of a position whose automatic pause took `previous` away.
    fn suspension_taking(previous: Option<PreviousBody>) -> SuspensionBody {
        SuspensionBody {
            at: None,
            auto: true,
            version: None,
            event_id: None,
            reason: None,
            previous,
            fallback: FallbackBody {
                kind: None,
                basis: "none",
                word: None,
            },
            evidence_now: Vec::new(),
            acknowledged: false,
        }
    }

    #[test]
    fn a_field_position_with_an_action_is_not_estimated() {
        let path = slot_row(
            "GET /doctor/{id} path[1]",
            PositionState::Proposed,
            Origin::Rule,
            Some("doctor"),
            false,
        );
        let field = slot_row(
            "GET /api/appointments [].doc_id",
            PositionState::Proposed,
            Origin::Rule,
            Some("doctor"),
            false,
        );
        let confirmed = slot_row(
            "GET /api/appointments [].doc_id",
            PositionState::Confirmed,
            Origin::Admin,
            Some("doctor"),
            true,
        );
        assert!(action_is_estimated(&path));
        assert!(!action_is_estimated(&field));
        // A confirmed position has no main action, so there is nothing to estimate.
        assert!(action_is_estimated(&confirmed));
    }

    #[test]
    fn a_path_key_is_one_that_ends_in_its_segment() {
        assert!(is_path_key("GET /doctor/{id} path[1]"));
        assert!(!is_path_key("GET /api/appointments [].doc_id"));
        assert!(!is_path_key("GET /doctor/{id} path"));
        assert!(!is_path_key("GET /doctor/{id}"));
    }

    #[test]
    fn a_position_has_the_main_action_its_state_and_entry_allow() {
        const KEY: &str = "GET /doctor/{id} path[1]";
        const NEW: &str = "GET /document/{id} path[1]";
        let previous = PreviousBody {
            class: Some("doctor".to_owned()),
            source: Some(Origin::Admin),
            confirmed_at: None,
            confirmed_by: None,
        };
        // A stopped entry is restored from the entry its pause took away.
        let stopped = SlotRow {
            suspension: Some(suspension_taking(Some(previous))),
            ..slot_row(
                KEY,
                PositionState::Suspended,
                Origin::Rule,
                Some("doctor"),
                false,
            )
        };
        assert_eq!(
            main_action(&stopped),
            Some(MainAction::Restore {
                class: "doctor".to_owned(),
                source: SlotSource::Admin,
            })
        );
        // Without that entry there is nothing to restore.
        let unknown = SlotRow {
            suspension: Some(suspension_taking(None)),
            ..slot_row(
                KEY,
                PositionState::Suspended,
                Origin::Rule,
                Some("doctor"),
                false,
            )
        };
        assert_eq!(main_action(&unknown), None);
        // An entry still in effect is paused.
        let active = SlotRow {
            suspension: Some(suspension_taking(None)),
            ..slot_row(
                KEY,
                PositionState::Suspended,
                Origin::Rule,
                Some("doctor"),
                true,
            )
        };
        assert_eq!(main_action(&active), Some(MainAction::Pause));
        // A proposal is confirmed as its kind, and a pending one without a kind has nothing to
        // confirm.
        let proposal = slot_row(
            NEW,
            PositionState::Proposed,
            Origin::Agent,
            Some("document"),
            false,
        );
        assert_eq!(
            main_action(&proposal),
            Some(MainAction::Confirm {
                class: "document".to_owned(),
                source: SlotSource::Agent,
            })
        );
        let pending = slot_row(NEW, PositionState::Pending, Origin::Rule, None, false);
        assert_eq!(main_action(&pending), None);
        // A confirmed, ambiguous or retired position has no main action.
        let confirmed = slot_row(
            KEY,
            PositionState::Confirmed,
            Origin::Admin,
            Some("doctor"),
            true,
        );
        assert_eq!(main_action(&confirmed), None);
        let ambiguous = slot_row(
            KEY,
            PositionState::Ambiguous,
            Origin::Rule,
            Some("doctor"),
            false,
        );
        assert_eq!(main_action(&ambiguous), None);
    }

    #[test]
    fn an_action_moves_the_kind_of_the_position_it_names() {
        const KEY: &str = "GET /doctor/{id} path[1]";
        const NEW: &str = "GET /document/{id} path[1]";
        let objects = spec().objects().clone();
        // A pause takes the kind away, and the restore that follows gives back the entry's kind.
        let paused = objects_after(&objects, KEY, &MainAction::Pause);
        assert_eq!(paused.class_of(KEY), None);
        let restored = objects_after(
            &paused,
            KEY,
            &MainAction::Restore {
                class: "doctor".to_owned(),
                source: SlotSource::Admin,
            },
        );
        assert_eq!(restored.class_of(KEY), Some("doctor"));
        // A confirmed proposal adds an entry the map did not declare.
        assert_eq!(objects.class_of(NEW), None);
        let confirmed = objects_after(
            &objects,
            NEW,
            &MainAction::Confirm {
                class: "document".to_owned(),
                source: SlotSource::Rule,
            },
        );
        assert_eq!(confirmed.class_of(NEW), Some("document"));
    }
}

/// Passes against a migrated PostgreSQL database, which they need `XSHIELD_DATABASE_URL` for.
/// Each creates one site of its own, named after the process.
#[cfg(test)]
mod live_tests {
    use std::collections::BTreeMap;

    use axum::{
        body::Bytes,
        http::{HeaderMap, HeaderValue, header},
    };
    use serde_json::json;
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use xshield_core::context::learning::{Vote, day_of};
    use xshield_postgres::{
        object_learning_store::{Judgement, LearnedState, Source},
        site_spec_store,
    };

    use super::*;

    const APPOINTMENTS: &str = "GET /api/appointments [].doc_id";
    const SLOT: &str = "GET /doctor/{id} path[1]";
    const OTHER: &str = "GET /other/{id} path[1]";

    async fn live_state() -> Arc<ControlState> {
        let url = std::env::var("XSHIELD_DATABASE_URL").expect("XSHIELD_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .connect(&url)
            .await
            .expect("connect to XSHIELD_DATABASE_URL");
        let hash = crate::hash_password("object-map-test").expect("hash_password");
        ControlState::new(pool, hash, None, false, None).expect("valid admin password hash")
    }

    fn site_spec(name: &str) -> SiteSpec {
        SiteSpec::from_json(
            &json!({
                "name": name,
                "hosts": [format!("{name}.example.com")],
                "origin": "http://10.0.0.5:8080",
                "session": {"cookie": "SESSIONID"},
                "entries": ["/login"],
                "objects": {
                    "classes": [{"id": "doctor", "name": "医生"}],
                    "slots": [{"key": APPOINTMENTS, "class": "doctor", "source": "admin"}]
                }
            })
            .to_string(),
        )
        .expect("the test spec")
    }

    /// A site with one declared position, one seen request position without a proposal, and
    /// one proposal of the rules, as the learning pass leaves them. `tag` keeps the sites of
    /// the tests that run in parallel apart.
    async fn seeded_site(tag: &str) -> (Arc<ControlState>, String) {
        let state = live_state().await;
        let name = format!("objects-{}-{tag}", std::process::id());
        site_spec_store::create(&state.pool, &site_spec(&name), None)
            .await
            .expect("create the site");
        // Created three days ago, so the decisions the tests place in the last days come
        // after its creation, as they would on a site that has been up for a while.
        sqlx::query("UPDATE site_configs SET created_at = $2 WHERE name = $1")
            .bind(&name)
            .bind(
                chrono::DateTime::from_timestamp_millis(now_millis() - 3 * DAY_MILLIS)
                    .expect("a time"),
            )
            .execute(&state.pool)
            .await
            .expect("backdate the site");
        let generation = site_spec_store::get(&state.pool, &name)
            .await
            .expect("read the site")
            .expect("the site exists")
            .created_at;
        let now = now_millis();
        let today = day_of(u64::try_from(now).unwrap_or(0));
        // One session's vote from the declared appointments position to the doctor position.
        let votes = [Vote {
            slot: SLOT.to_owned(),
            session: "a".to_owned(),
            day: today,
            from: vec![APPOINTMENTS.to_owned()],
        }];
        store::record_evidence(&state.pool, &name, generation, &votes, &[])
            .await
            .expect("record the vote");
        let proposal = Judgement {
            slot: OTHER,
            state: LearnedState::Proposed,
            class: "doctor",
            votes: 20,
            sessions: 5,
            share_per_mille: 950,
            last_day: today,
            source: Source::Rule,
        };
        store::put_judgement(&state.pool, &name, generation, &proposal, now)
            .await
            .expect("judge the other position");
        (state, name)
    }

    /// The listing the API returns for `query`, as JSON.
    async fn listed(state: &Arc<ControlState>, name: &str, query: &[(&str, &str)]) -> Value {
        let query: BTreeMap<String, String> = query
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let body = list(
            State(Arc::clone(state)),
            Path(name.to_owned()),
            Query(query),
        )
        .await
        .expect("list the positions")
        .0;
        serde_json::to_value(body).expect("the listing as JSON")
    }

    /// The id of the listed position with `key`.
    fn id_of(listing: &Value, key: &str) -> String {
        listing["slots"]
            .as_array()
            .expect("the slots")
            .iter()
            .find(|row| row["key"] == key)
            .expect("the position is listed")["id"]
            .as_str()
            .expect("an id")
            .to_owned()
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn the_map_lists_its_positions_and_explains_their_flows() {
        let (state, name) = seeded_site("lists").await;
        let all = listed(&state, &name, &[]).await;
        assert_eq!(all["counts"]["classes"], 1);
        assert_eq!(all["counts"]["confirmed"], 1);
        assert_eq!(all["counts"]["pending"], 1);
        assert_eq!(all["counts"]["proposed"], 1);
        assert_eq!(all["agent_configured"], false);
        assert_eq!(all["classes"][0]["slot_count"], 2);
        assert_eq!(
            all["classes"][0]["routes"],
            json!(["/api/appointments", "/other/{id}"])
        );

        let proposed = listed(&state, &name, &[("state", "proposed")]).await;
        assert_eq!(proposed["slots"][0]["key"], OTHER);
        assert_eq!(proposed["slots"][0]["source"], "rule");
        assert_eq!(proposed["slots"][0]["dismissed"], false);
        assert!(
            proposed["slots"][0]["id"]
                .as_str()
                .is_some_and(|id| id.starts_with('s'))
        );

        // The declared position's detail: the request that reached it, from one session.
        let declared = declared_id(APPOINTMENTS);
        let detail = slot(State(Arc::clone(&state)), Path((name.clone(), declared)))
            .await
            .expect("the declared position")
            .0;
        let detail = serde_json::to_value(detail).expect("the detail as JSON");
        assert_eq!(detail["state"], "confirmed");
        assert_eq!(detail["side"], "response");
        assert_eq!(detail["flows_in"][0]["key"], SLOT);
        assert_eq!(detail["flows_in"][0]["side"], "request");
        assert_eq!(detail["flows_in"][0]["uses"], 1);
        assert_eq!(detail["flows_in"][0]["share"], 1.0);
        assert_eq!(detail["history"], json!([]));

        let unknown_slot = slot(
            State(Arc::clone(&state)),
            Path((name.clone(), "s999999999".to_owned())),
        )
        .await
        .expect_err("an id that names no position");
        assert_eq!(unknown_slot.status(), StatusCode::NOT_FOUND);
        let unknown_site = list(
            State(Arc::clone(&state)),
            Path("no-such-site".to_owned()),
            Query(BTreeMap::new()),
        )
        .await
        .expect_err("an unknown site");
        assert_eq!(unknown_site.status(), StatusCode::NOT_FOUND);
        let bad_state = list(
            State(Arc::clone(&state)),
            Path(name.clone()),
            Query(BTreeMap::from([(
                "state".to_owned(),
                "dismissed".to_owned(),
            )])),
        )
        .await
        .expect_err("a state that is not one");
        assert_eq!(bad_state.status(), StatusCode::BAD_REQUEST);
        let candidates = bootstrap(State(Arc::clone(&state)), Path(name.clone()))
            .await
            .expect("bootstrap")
            .0;
        assert_eq!(candidates.window_hours, BOOTSTRAP_WINDOW_HOURS);
        assert!(candidates.candidates.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn bootstrap_counts_the_last_day_of_decisions_and_skips_declared_positions() {
        let (state, name) = seeded_site("bootstrap").await;
        let now = now_millis();
        crate::test_support::ensure_days(&state.pool, &[now, now - 2 * DAY_MILLIS]).await;
        let minutes_ago = |minutes: i64| now - minutes * 60_000;
        // Three uses of the doctor position in the window, by two sessions, and one use a day
        // older than the window, which counts for nothing.
        decide(
            &state.pool,
            &name,
            minutes_ago(5),
            "req_boot_1",
            "a",
            "fast_allow",
            json!([value(SLOT, APPOINTMENTS, "req_boot_r1")]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            minutes_ago(4),
            "req_boot_2",
            "b",
            "fast_allow",
            json!([value(SLOT, APPOINTMENTS, "req_boot_r2")]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            minutes_ago(3),
            "req_boot_3",
            "b",
            "fast_allow",
            json!([value(SLOT, APPOINTMENTS, "req_boot_r3")]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            now - 2 * DAY_MILLIS,
            "req_boot_4",
            "c",
            "fast_allow",
            json!([value(SLOT, APPOINTMENTS, "req_boot_r4")]),
        )
        .await;
        let body = bootstrap(State(Arc::clone(&state)), Path(name.clone()))
            .await
            .expect("bootstrap")
            .0;
        assert_eq!(body.records, 3);
        // The response position the site declares is not a candidate; the doctor position is.
        let keys: Vec<&str> = body
            .candidates
            .iter()
            .filter_map(|candidate| candidate["key"].as_str())
            .collect();
        assert_eq!(keys, [SLOT]);
        let candidate = &body.candidates[0];
        assert_eq!(
            (candidate["uses"].as_u64(), candidate["sessions"].as_u64()),
            (Some(3), Some(2))
        );
        assert_eq!(
            (
                candidate["kind"].as_str(),
                candidate["name"].as_str(),
                candidate["reason"]["code"].as_str(),
            ),
            (Some("doctor"), Some("医生"), Some("route_word"))
        );
        assert!(candidate["note"].is_null());
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_proposal_is_dismissed_and_stays_listed_while_declared_positions_are_refused() {
        let (state, name) = seeded_site("dismissal").await;
        let proposed_id = id_of(&listed(&state, &name, &[]).await, OTHER);
        let status = dismiss(
            State(Arc::clone(&state)),
            Path((name.clone(), proposed_id.clone())),
        )
        .await
        .expect("dismiss the proposal");
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Dismissed, the position is listed as pending with its flag, and the proposal is gone.
        let pending = listed(&state, &name, &[("state", "pending")]).await;
        let dismissed = pending["slots"]
            .as_array()
            .expect("the slots")
            .iter()
            .find(|row| row["key"] == OTHER)
            .expect("the dismissed position stays listed")
            .clone();
        assert_eq!(dismissed["id"], proposed_id);
        assert_eq!(dismissed["dismissed"], true);
        assert!(dismissed["class"].is_null());
        assert_eq!(listed(&state, &name, &[]).await["counts"]["proposed"], 0);

        // The seen request position can be marked ambiguous, and then it is counted as such.
        let seen_id = id_of(&pending, SLOT);
        let status = ambiguous(State(Arc::clone(&state)), Path((name.clone(), seen_id)))
            .await
            .expect("mark the seen position ambiguous");
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(listed(&state, &name, &[]).await["counts"]["ambiguous"], 1);

        // Declared positions are the configuration's to change, and an unknown id is not found.
        let refused = dismiss(
            State(Arc::clone(&state)),
            Path((name.clone(), declared_id(APPOINTMENTS))),
        )
        .await
        .expect_err("a declared position is refused");
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        let missing = ambiguous(
            State(Arc::clone(&state)),
            Path((name.clone(), "s999999999".to_owned())),
        )
        .await
        .expect_err("an id that names no position");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    /// A decision row of the gateway for a `GET /doctor/7` request of `session`, judged as
    /// `decision_path` says. Jev judged the request when the path starts with `jev_`.
    async fn decide(
        pool: &PgPool,
        site: &str,
        at_millis: i64,
        request_id: &str,
        session: &str,
        decision_path: &str,
        values: Value,
    ) {
        let (outcome, status) = if decision_path == "jev_deny" {
            ("blocked", 403_i16)
        } else {
            ("allowed", 200_i16)
        };
        let jev = decision_path.starts_with("jev_").then(|| json!({"v": 1}));
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace, jev)
             VALUES ($1, $2, $3, 'edge-1', 'clinic.example.com', '10.0.0.1', $4,
                'GET', '/doctor/7', $5, $6, $7, $8, $9)",
        )
        .bind(at_millis)
        .bind(request_id)
        .bind(site)
        .bind(session)
        .bind(status)
        .bind(decision_path)
        .bind(outcome)
        .bind(json!({"v": 1, "values": values}))
        .bind(jev)
        .execute(pool)
        .await
        .expect("insert a decision row");
    }

    /// The value of a request at `slot` that the session saw in the response `source_request`
    /// showed at `source`, with no time of observation.
    fn value(slot: &str, source: &str, source_request: &str) -> Value {
        seen_value(slot, source, source_request, None)
    }

    /// [`value`] for a response observed at `observed_millis`, Unix milliseconds if known.
    fn seen_value(
        slot: &str,
        source: &str,
        source_request: &str,
        observed_millis: Option<i64>,
    ) -> Value {
        json!({
            "at": "path[1]", "key": null, "value": "7", "kind": "reference",
            "inert": false, "seen": true, "verified": false, "slot": slot,
            "sources": [{
                "field": "doc_id", "request": "GET /api/appointments",
                "request_id": source_request, "at_millis": observed_millis, "slot": source
            }]
        })
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn the_drawer_names_the_newest_requests_and_the_jev_decisions_on_each_flow() {
        let (state, name) = seeded_site("drawer").await;
        let now = now_millis();
        crate::test_support::ensure_days(
            &state.pool,
            &[now, now - DAY_MILLIS, now - 2 * DAY_MILLIS],
        )
        .await;
        // Four uses of the doctor position: Jev allowed two and refused one, one was a fast
        // allow, and the oldest is two days old. Each one's value was shown by a response.
        let minutes_ago = |minutes: i64| now - minutes * 60_000;
        decide(
            &state.pool,
            &name,
            minutes_ago(3),
            "req_consumer_1",
            "a",
            "jev_allow",
            json!([value(SLOT, APPOINTMENTS, "req_response_1")]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            minutes_ago(2),
            "req_consumer_2",
            "b",
            "jev_deny",
            json!([value(SLOT, APPOINTMENTS, "req_response_2")]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            minutes_ago(1),
            "req_consumer_3",
            "c",
            "fast_allow",
            json!([value(SLOT, APPOINTMENTS, "req_response_3")]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            now - 2 * DAY_MILLIS,
            "req_consumer_4",
            "a",
            "jev_allow",
            json!([value(SLOT, APPOINTMENTS, "req_response_4")]),
        )
        .await;

        let listing = listed(&state, &name, &[]).await;
        let doctor = slot(
            State(Arc::clone(&state)),
            Path((name.clone(), id_of(&listing, SLOT))),
        )
        .await
        .expect("the doctor position")
        .0;
        let doctor = serde_json::to_value(doctor).expect("the detail as JSON");
        // The request position: its newest three requests, and the Jev decisions on its flow.
        assert_eq!(
            doctor["examples"],
            json!(["req_consumer_3", "req_consumer_2", "req_consumer_1"])
        );
        assert_eq!(doctor["flows_in"][0]["key"], APPOINTMENTS);
        assert_eq!(doctor["flows_in"][0]["uses"], 1);
        assert_eq!(doctor["flows_in"][0]["jev_allow"], 2);
        assert_eq!(doctor["flows_in"][0]["jev_deny"], 1);

        // The response position: the responses that showed its value, newest first, and the
        // Jev decisions on the requests that used it.
        let appointments = slot(
            State(Arc::clone(&state)),
            Path((name.clone(), declared_id(APPOINTMENTS))),
        )
        .await
        .expect("the declared position")
        .0;
        let appointments = serde_json::to_value(appointments).expect("the detail as JSON");
        assert_eq!(
            appointments["examples"],
            json!(["req_response_3", "req_response_2", "req_response_1"])
        );
        assert_eq!(appointments["flows_in"][0]["key"], SLOT);
        assert_eq!(appointments["flows_in"][0]["jev_allow"], 2);
        assert_eq!(appointments["flows_in"][0]["jev_deny"], 1);

        // A position nothing used has no examples and no decisions.
        let other = slot(
            State(Arc::clone(&state)),
            Path((name.clone(), id_of(&listing, OTHER))),
        )
        .await
        .expect("the proposed position")
        .0;
        let other = serde_json::to_value(other).expect("the detail as JSON");
        assert_eq!(other["examples"], json!([]));
        assert_eq!(other["flows_in"], json!([]));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_proposed_path_position_previews_the_calls_its_confirmation_allows() {
        let (state, name) = seeded_site("path-impact").await;
        let id = id_of(&listed(&state, &name, &[]).await, OTHER);
        // Jev allowed a call to /other/7, and the declared appointments position showed the value
        // as a doctor. Confirming the proposal verifies the value, so the call becomes a fast allow.
        let at = now_millis() - 1_000;
        crate::test_support::ensure_days(&state.pool, &[at]).await;
        sqlx::query(
            "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                method, path, status, decision_path, outcome, trace, jev)
             VALUES ($1, 'req_call', $2, 'edge-1', 'clinic.example.com', '10.0.0.1', 'a',
                'GET', '/other/7', 200, 'jev_allow', 'allowed', $3, $4)",
        )
        .bind(at)
        .bind(&name)
        .bind(json!({"v": 1, "values": [seen_value(OTHER, APPOINTMENTS, "req_shown", Some(at))]}))
        .bind(json!({"v": 1}))
        .execute(&state.pool)
        .await
        .expect("insert a decision row");
        let body = slot(State(Arc::clone(&state)), Path((name, id)))
            .await
            .expect("the drawer reads")
            .0;
        let body = serde_json::to_value(body).expect("the drawer as JSON");
        assert_eq!(body["impact_complete"], json!(true));
        assert_eq!(body["impact"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["impact"][0]["kind"], "new_fast_allow");
        assert_eq!(body["impact"][0]["count"], 1);
        assert_eq!(body["impact"][0]["sample"], "req_call");
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_path_impact_leaves_out_the_decisions_from_before_the_site_was_created() {
        let (state, name) = seeded_site("path-impact-recreated").await;
        // The site was created two hours ago. A decision from five hours ago belongs to a deleted
        // site of the same name, and a decision from an hour ago belongs to this one.
        let created = now_millis() - 2 * 60 * 60_000;
        sqlx::query("UPDATE site_configs SET created_at = $2 WHERE name = $1")
            .bind(&name)
            .bind(chrono::DateTime::from_timestamp_millis(created).expect("a time"))
            .execute(&state.pool)
            .await
            .expect("set the creation time");
        let id = id_of(&listed(&state, &name, &[]).await, OTHER);
        let before = now_millis() - 5 * 60 * 60_000;
        let after = now_millis() - 60 * 60_000;
        crate::test_support::ensure_days(&state.pool, &[before, after]).await;
        for (at, request) in [(before, "req_deleted_site"), (after, "req_new_site")] {
            sqlx::query(
                "INSERT INTO decision_log (at_millis, request_id, site, edge, host, client, session,
                    method, path, status, decision_path, outcome, trace, jev)
                 VALUES ($1, $2, $3, 'edge-1', 'clinic.example.com', '10.0.0.1', 'a',
                    'GET', '/other/7', 200, 'jev_allow', 'allowed', $4, $5)",
            )
            .bind(at)
            .bind(request)
            .bind(&name)
            .bind(json!({"v": 1, "values": [seen_value(OTHER, APPOINTMENTS, "req_shown", Some(at))]}))
            .bind(json!({"v": 1}))
            .execute(&state.pool)
            .await
            .expect("insert a decision row");
        }
        let body = slot(State(Arc::clone(&state)), Path((name, id)))
            .await
            .expect("the drawer reads")
            .0;
        let body = serde_json::to_value(body).expect("the drawer as JSON");
        assert_eq!(body["impact_estimated"], json!(true));
        assert_eq!(body["impact_complete"], json!(true));
        assert_eq!(body["impact"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["impact"][0]["count"], 1);
        assert_eq!(body["impact"][0]["sample"], "req_new_site");
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_response_lists_the_responses_it_showed_newest_observed_first() {
        let (state, name) = seeded_site("observed").await;
        let now = now_millis();
        crate::test_support::ensure_days(&state.pool, &[now - 4 * DAY_MILLIS, now]).await;
        let minutes_ago = |minutes: i64| now - minutes * 60_000;
        // The response observed ten minutes ago is reused first, and the one observed thirty
        // minutes ago is reused last, so the reuse order is the reverse of the observation order.
        decide(
            &state.pool,
            &name,
            minutes_ago(5),
            "req_reuses_late",
            "a",
            "jev_allow",
            json!([seen_value(
                SLOT,
                APPOINTMENTS,
                "resp_late",
                Some(minutes_ago(10))
            )]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            minutes_ago(1),
            "req_reuses_early",
            "b",
            "jev_allow",
            json!([seen_value(
                SLOT,
                APPOINTMENTS,
                "resp_early",
                Some(minutes_ago(30))
            )]),
        )
        .await;
        let appointments = slot(
            State(Arc::clone(&state)),
            Path((name.clone(), declared_id(APPOINTMENTS))),
        )
        .await
        .expect("the declared position")
        .0;
        let appointments = serde_json::to_value(appointments).expect("the detail as JSON");
        assert_eq!(appointments["examples"], json!(["resp_late", "resp_early"]));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_site_created_again_under_its_name_reads_none_of_the_decisions_before_it() {
        let (state, name) = seeded_site("recreated").await;
        let now = now_millis();
        crate::test_support::ensure_days(&state.pool, &[now - 4 * DAY_MILLIS, now]).await;
        // The decision log keeps the rows of a deleted site. The one from four days ago is
        // inside the learning window but before the site was created three days ago.
        decide(
            &state.pool,
            &name,
            now - 4 * DAY_MILLIS,
            "req_before",
            "a",
            "jev_deny",
            json!([value(SLOT, APPOINTMENTS, "resp_before")]),
        )
        .await;
        decide(
            &state.pool,
            &name,
            now - 60_000,
            "req_after",
            "b",
            "jev_allow",
            json!([value(SLOT, APPOINTMENTS, "resp_after")]),
        )
        .await;
        let listing = listed(&state, &name, &[]).await;
        let doctor = slot(
            State(Arc::clone(&state)),
            Path((name.clone(), id_of(&listing, SLOT))),
        )
        .await
        .expect("the doctor position")
        .0;
        let doctor = serde_json::to_value(doctor).expect("the detail as JSON");
        assert_eq!(doctor["examples"], json!(["req_after"]));
        assert_eq!(doctor["flows_in"][0]["key"], APPOINTMENTS);
        assert_eq!(doctor["flows_in"][0]["jev_allow"], 1);
        assert_eq!(doctor["flows_in"][0]["jev_deny"], 0);
    }

    /// The configuration of the test site, with its declared position paused or not, as the
    /// learning pass and the console write it.
    fn site_with_pause(name: &str, paused: bool) -> SiteSpec {
        SiteSpec::from_json(
            &json!({
                "name": name,
                "hosts": [format!("{name}.example.com")],
                "origin": "http://10.0.0.5:8080",
                "session": {"cookie": "SESSIONID"},
                "entries": ["/login"],
                "objects": {
                    "classes": [{"id": "doctor", "name": "医生"}],
                    "slots": [{"key": APPOINTMENTS, "class": "doctor", "source": "admin", "paused": paused}]
                }
            })
            .to_string(),
        )
        .expect("the test spec")
    }

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers
    }

    /// The events of the test site for `query`, as JSON.
    async fn events_of(state: &Arc<ControlState>, name: &str, query: &[(&str, &str)]) -> Value {
        let query: BTreeMap<String, String> = query
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let Json(body) = events(
            State(Arc::clone(state)),
            Path(name.to_owned()),
            Query(query),
        )
        .await
        .expect("the events");
        serde_json::to_value(body).expect("the events as JSON")
    }

    async fn version_of(state: &Arc<ControlState>, name: &str) -> i64 {
        site_spec_store::get(&state.pool, name)
            .await
            .expect("read the site")
            .expect("the site exists")
            .version
    }

    /// A site whose declared position the learning pass paused in version 2, with the position
    /// suspended: the state a pause leaves. Returns the state and the name of the site.
    async fn paused_site(tag: &str) -> (Arc<ControlState>, String) {
        let (state, name) = seeded_site(tag).await;
        site_spec_store::write(
            &state.pool,
            &name,
            &site_with_pause(&name, true),
            1,
            site_spec_store::Change::AutoPause,
            Some("学习任务自动暂停了 1 个位置"),
        )
        .await
        .expect("the pause");
        let record = site_of(&state, &name).await.expect("the site");
        assert_eq!(record.version, 2);
        store::put_judgement(
            &state.pool,
            &name,
            record.created_at,
            &Judgement {
                slot: APPOINTMENTS,
                state: LearnedState::Suspended,
                class: "doctor",
                votes: 20,
                sessions: 5,
                share_per_mille: 100,
                last_day: day_of(u64::try_from(now_millis()).unwrap_or(0)),
                source: Source::Rule,
            },
            now_millis(),
        )
        .await
        .expect("the suspended position");
        (state, name)
    }

    /// A save of the site's configuration, with the declared position paused or not, that names
    /// `event` when given.
    async fn save_with(
        state: &Arc<ControlState>,
        name: &str,
        paused: bool,
        expected: i64,
        event: Option<&str>,
    ) -> Result<(), ApiError> {
        let body = json!({
            "spec": site_with_pause(name, paused),
            "expected_version": expected,
            "object_event": event,
        });
        crate::sites::update(
            State(Arc::clone(state)),
            Path(name.to_owned()),
            json_headers(),
            Bytes::from(body.to_string()),
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_save_undoes_an_acknowledged_pause_and_confirms_its_position_again() {
        let (state, name) = paused_site("undo-pause").await;
        let today = day_of(u64::try_from(now_millis()).unwrap_or(0));
        let open = events_of(&state, &name, &[]).await;
        assert_eq!(open["events"][0]["id"], "v2-0");
        assert_eq!(open["events"][0]["status"], "open");
        // Acknowledging the pause writes no version, and a second acknowledgement changes nothing.
        for _ in 0..2 {
            let status = ack_event(
                State(Arc::clone(&state)),
                Path((name.clone(), "v2-0".to_owned())),
            )
            .await
            .expect("the acknowledgement");
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        assert_eq!(events_of(&state, &name, &[]).await["events"], json!([]));
        let acknowledged = events_of(&state, &name, &[("status", "all")]).await;
        assert_eq!(acknowledged["events"][0]["status"], "acknowledged");
        assert_eq!(version_of(&state, &name).await, 2);

        // The save that restores the entry names the event, and the event reads undone at version 3.
        save_with(&state, &name, false, 2, Some("v2-0"))
            .await
            .expect("the undo saves");
        let undone = events_of(&state, &name, &[("status", "all")]).await;
        assert_eq!(undone["events"][0]["status"], "undone");
        assert_eq!(undone["events"][0]["handled"]["version"], 3);
        // The position is confirmed again, and the evidence before tomorrow stops counting for it.
        let (position_state, baseline): (String, Option<i64>) = sqlx::query_as(
            "SELECT state, baseline_day FROM object_positions WHERE site = $1 AND slot = $2",
        )
        .bind(&name)
        .bind(APPOINTMENTS)
        .fetch_one(&state.pool)
        .await
        .expect("the position");
        assert_eq!(position_state, "confirmed");
        assert_eq!(baseline, Some(i64::try_from(today + 1).expect("a day")));
    }

    #[tokio::test]
    #[ignore = "requires a reachable PostgreSQL database (XSHIELD_DATABASE_URL)"]
    async fn a_save_refuses_an_event_it_cannot_undo_and_an_unknown_one() {
        let (state, name) = paused_site("refuse-undo").await;
        save_with(&state, &name, false, 2, Some("v2-0"))
            .await
            .expect("the undo saves");
        // An undone event takes no further handling.
        let Err(refused) = ack_event(
            State(Arc::clone(&state)),
            Path((name.clone(), "v2-0".to_owned())),
        )
        .await
        else {
            panic!("an undone event is acknowledged");
        };
        assert_eq!(refused.code(), "EVENT_UNDONE");
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        // A save naming an event that does not exist writes nothing.
        let Err(unknown) = save_with(&state, &name, true, 3, Some("v9-9")).await else {
            panic!("a save names an unknown event");
        };
        assert_eq!(unknown.code(), "EVENT_NOT_FOUND");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(version_of(&state, &name).await, 3);
    }
}
