//! The object map of one site (console design section 7 and object-map design sections
//! 1 to 5): the positions the console lists, one position's drawer, the dismiss and
//! ambiguous actions, and the bootstrap candidates.
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
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use xshield_core::{
    context::{
        ObjectSlot, SiteSpec, SlotSource,
        learning::{RETIRE_DAYS, WINDOW_DAYS, day_of, observe},
    },
    kind::{NameReason, NameSource, Rules, request_name, response_name},
};
use xshield_postgres::{
    object_learning_store::{self as store, Flow, JevFlow, PositionRow},
    site_spec_store::{self, SiteRecord},
};

use crate::{
    ControlState,
    error::{ApiError, ApiResult},
    params::{DAY_MILLIS, Params, now_millis, rfc3339},
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
    classes: Vec<ClassBody>,
    slots: Vec<SlotRow>,
    /// Which automatic behaviours this build runs, so the console can say which are off.
    features: Features,
    /// The automatic changes of the last 30 days, newest first: one event per entry changed.
    events: Vec<Value>,
}

/// The automatic behaviours this build runs: `features` of the object map's response.
#[derive(Debug, Serialize)]
pub(crate) struct Features {
    auto_tighten: bool,
    auto_pause: bool,
    path_confirm: bool,
}

/// What this build runs. Tightening is not applied on its own yet, and path positions cannot be
/// confirmed from the console yet.
const FEATURES: Features = Features {
    auto_tighten: false,
    auto_pause: true,
    path_confirm: false,
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

/// `GET /objects/slots/{id}`: `ObjectSlotDetail`. The shape, history and impact are empty
/// until their sources are read.
#[derive(Debug, Serialize)]
pub(crate) struct SlotBody {
    #[serde(flatten)]
    row: SlotRow,
    flows_in: Vec<FlowBody>,
    /// Request ids of the newest uses of the position, at most three.
    examples: Vec<String>,
    shape: Vec<Value>,
    history: Vec<Value>,
    impact: Vec<Value>,
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

/// The filters of the list: a state, a kind, and text the key or the kind's id contains.
struct Filter {
    state: Option<PositionState>,
    class: Option<String>,
    text: Option<String>,
}

impl Filter {
    /// # Errors
    /// `INVALID_FILTER` naming `state` when the value is not a position state.
    fn of(params: &Params) -> ApiResult<Self> {
        let state = params
            .text("state")
            .map(|value| {
                PositionState::parse(value).ok_or_else(|| ApiError::invalid_filter("state"))
            })
            .transpose()?;
        Ok(Self {
            state,
            class: params.text("class").map(str::to_owned),
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
        state && class && text
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
    let learned = store::positions(&state.pool, &name).await?;
    let rows = merged(&record.spec, &learned)?;
    let classes = record.spec.objects().classes().len();
    Ok(Json(ObjectsBody {
        counts: counts_of(classes, &rows),
        agent_configured: false,
        classes: classes_of(&record.spec, &rows),
        slots: rows.into_iter().filter(|row| filter.matches(row)).collect(),
        features: FEATURES,
        events: automatic_events(&state, &name).await?,
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
    let learned = store::positions(&state.pool, &name).await?;
    let row = merged(&record.spec, &learned)?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(slot_not_found)?;
    let side = row.side;
    let now = now_millis();
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
    Ok(Json(SlotBody {
        row,
        flows_in: flow_bodies(side.opposite(), total, flows, &decisions),
        examples,
        shape: Vec::new(),
        history: Vec::new(),
        impact: Vec::new(),
    }))
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
/// version changed, with the entry it replaced and the entry it became. Every event is `open`: the
/// console's acknowledgements are not recorded yet.
///
/// # Errors
/// A 500 when a read of the configuration history fails.
async fn automatic_events(state: &ControlState, name: &str) -> ApiResult<Vec<Value>> {
    let since = now_millis().saturating_sub(EVENTS_DAYS.saturating_mul(DAY_MILLIS));
    let versions = site_spec_store::automatic_history(&state.pool, name, EVENTS_MAX).await?;
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
            events.push(automatic_event(&version, index, previous, slot));
        }
    }
    Ok(events)
}

/// One automatic change in the shape the console reads: the entry it replaced and the entry it
/// became, the side of the position, and the reason. A pause is for evidence that points at other
/// kinds. The status is `open` until the console acknowledges or undoes the event, which is not
/// recorded yet.
fn automatic_event(
    version: &site_spec_store::HistoryEntry,
    index: usize,
    previous: Option<&ObjectSlot>,
    slot: &ObjectSlot,
) -> Value {
    let reason = (version.change == site_spec_store::Change::AutoPause)
        .then(|| serde_json::json!({ "code": "evidence_drift" }));
    serde_json::json!({
        "id": format!("v{}-{index}", version.version),
        "kind": version.change.as_str(),
        "at": version.changed_at.to_rfc3339(),
        "version": version.version,
        "key": slot.key,
        "side": side_of_key(&slot.key).as_str(),
        "before": { "class": previous.map(|entry| entry.class.as_str()), "entry": previous },
        "after": { "class": slot.class, "entry": slot },
        "reason": reason,
        "impact": [],
        "examples": [],
        "status": "open",
        "handled": null,
        "note": version.note,
    })
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
async fn site_of(state: &ControlState, name: &str) -> ApiResult<SiteRecord> {
    site_spec_store::get(&state.pool, name)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "SITE_NOT_FOUND"))
}

fn slot_not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "SLOT_NOT_FOUND")
}

/// The learned request position an action names. A declared position is decided by the
/// configuration, and a response position has no proposal, so both are refused.
///
/// # Errors
/// `SLOT_NOT_FOUND` (404) for an id that names no position of the site, `SLOT_IS_DECLARED`
/// and `SLOT_NOT_REQUEST` (409) for a position the action does not apply to, and a 500 when
/// a query fails.
async fn learned_request(
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
fn merged(spec: &SiteSpec, learned: &[PositionRow]) -> ApiResult<Vec<SlotRow>> {
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
            rows.push(learned_row(row)?);
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
    }
}

/// A learned position the configuration does not declare.
///
/// # Errors
/// `INTERNAL` when the stored state or side is not one this build reads.
fn learned_row(row: &PositionRow) -> ApiResult<SlotRow> {
    let state = PositionState::parse(&row.state)
        .ok_or_else(|| ApiError::internal("object position state", &row.state))?;
    let side = Side::parse(&row.side)
        .ok_or_else(|| ApiError::internal("object position side", &row.side))?;
    let basis = match state {
        PositionState::Retired => format!("超过 {RETIRE_DAYS} 天没有使用"),
        PositionState::Ambiguous => "已标为不确定，不再提议".to_owned(),
        _ if row.dismissed && row.class.is_none() => "已忽略，证据明显变化后再提议".to_owned(),
        _ if row.class.is_some() && row.votes > 0 => evidence_basis(row),
        _ => "学习中，尚无提议".to_owned(),
    };
    Ok(SlotRow {
        id: learned_id(row.id),
        side,
        key: row.slot.clone(),
        class: row.class.clone(),
        state,
        source: Origin::Rule,
        basis,
        last_seen: last_seen(row.last_day),
        dismissed: row.dismissed,
        in_effect: false,
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
fn learned_id(id: i64) -> String {
    format!("s{id}")
}

/// The learned row an id names, when the id has the learned form.
fn learned_row_id(id: &str) -> Option<i64> {
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
fn oldest_day(now: i64) -> u64 {
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
        let rows = merged(&spec(), &learned).unwrap();
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
        let error = learned_row(&row(1, "GET /x path[1]", "request", "bogus", None)).unwrap_err();
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn counts_leave_retired_positions_out_and_filters_match_their_fields() {
        let learned = [
            row(1, "GET /other/{id} path[1]", "request", "pending", None),
            row(2, "GET /old/{id} path[1]", "request", "retired", None),
        ];
        let rows = merged(&spec(), &learned).unwrap();
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
        let event = automatic_event(
            &version,
            0,
            Some(&before.objects().slots()[0]),
            &paused.objects().slots()[0],
        );
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
}

/// Passes against a migrated PostgreSQL database, which they need `XSHIELD_DATABASE_URL` for.
/// Each creates one site of its own, named after the process.
#[cfg(test)]
mod live_tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use xshield_core::context::learning::{Vote, day_of};
    use xshield_postgres::{
        object_learning_store::{Judgement, LearnedState},
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
        ControlState::new(pool, hash, None, false).expect("valid admin password hash")
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
}
