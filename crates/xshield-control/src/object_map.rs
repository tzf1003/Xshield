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
use xshield_core::context::{
    ObjectSlot, SiteSpec, SlotSource,
    learning::{RETIRE_DAYS, WINDOW_DAYS, day_of},
};
use xshield_postgres::{
    object_learning_store::{self as store, Flow, PositionRow},
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
    /// The automatic changes the banner shows. None are recorded yet, so empty.
    events: Vec<Value>,
}

/// One other end of a position's flows: `ObjectFlow`.
#[derive(Debug, Serialize)]
struct FlowBody {
    key: String,
    side: Side,
    share: f64,
    uses: i64,
    sessions: i64,
    /// Jev's decisions on the flow's requests. The evidence does not keep them yet, so 0.
    jev_allow: i64,
    jev_deny: i64,
    method: String,
    route: String,
}

/// `GET /objects/slots/{id}`: `ObjectSlotDetail`. The examples, shape, history and impact
/// are empty until their sources are read.
#[derive(Debug, Serialize)]
pub(crate) struct SlotBody {
    #[serde(flatten)]
    row: SlotRow,
    flows_in: Vec<FlowBody>,
    examples: Vec<String>,
    shape: Vec<Value>,
    history: Vec<Value>,
    impact: Vec<Value>,
}

/// `GET /objects/bootstrap`: `BootstrapResponse`. The candidates are not read yet, so empty.
#[derive(Debug, Serialize)]
pub(crate) struct BootstrapBody {
    window_hours: i64,
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
        events: Vec::new(),
    }))
}

/// `GET /api/sites/{name}/objects/slots/{id}`: one position with the flows of its values.
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
    let oldest = oldest_day(now_millis());
    let total = store::uses(&state.pool, &name, &row.key, side.as_str(), oldest).await?;
    let flows = store::flows(&state.pool, &name, &row.key, side.as_str(), oldest).await?;
    Ok(Json(SlotBody {
        row,
        flows_in: flows
            .into_iter()
            .map(|flow| flow_body(flow, side.opposite(), total))
            .collect(),
        examples: Vec::new(),
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

/// `GET /api/sites/{name}/objects/bootstrap`: the kinds the cold start can propose. The
/// candidates are not read yet, so the list is empty.
///
/// # Errors
/// `SITE_NOT_FOUND` for an unknown site.
pub async fn bootstrap(
    State(state): State<Arc<ControlState>>,
    Path(name): Path<String>,
) -> ApiResult<Json<BootstrapBody>> {
    site_of(&state, &name).await?;
    Ok(Json(BootstrapBody {
        window_hours: BOOTSTRAP_WINDOW_HOURS,
        candidates: Vec::new(),
    }))
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
    if spec.objects().class_of(&row.slot).is_some() {
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
        if objects.class_of(&row.slot).is_none() {
            rows.push(learned_row(row)?);
        }
    }
    Ok(rows)
}

/// A declared position: confirmed, or suspended when the learned row says its evidence now
/// points at other kinds. Its side comes from the learned row when there is one.
fn declared_row(slot: &ObjectSlot, learned: Option<&PositionRow>) -> SlotRow {
    let state = match learned {
        Some(row) if row.state == "suspended" => PositionState::Suspended,
        _ => PositionState::Confirmed,
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
    let digest = Sha256::digest(key.as_bytes());
    let mut id = String::with_capacity(1 + 2 * DIGEST_BYTES);
    id.push('a');
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
}

/// Passes against a migrated PostgreSQL database, which they need `XSHIELD_DATABASE_URL` for.
/// Each creates one site of its own, named after the process.
#[cfg(test)]
mod live_tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;
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
}
