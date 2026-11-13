//! The site's object map, the optional `objects` section of a site
//! (the object-map design note, section 1).
//!
//! A position is a place a value sits: a request location of one route
//! (`GET /doctor/{id} path[1]`) or a response field of one route
//! (`GET /api/appointments [].doc_id`). The map gives some positions a kind of
//! object (`doctor`). Two confirmed positions of the same kind hold the same
//! kind of object; two of different kinds do not, whatever their names say.
//!
//! Only confirmed entries live here. Proposals and evidence are kept by the
//! learning state, not by the site configuration. The learning settings
//! (`objects.learning`) are configuration, so a change to them is a new
//! configuration version, but they never change the map by themselves.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::config::ConfigError;
use super::learning::{SESSIONS_MIN, VOTES_MIN};
use crate::path_template::{canonical_path, is_plain_word, position_template};

/// Most object kinds one site declares.
pub const CLASSES_MAX: usize = 64;
/// Most confirmed positions one site holds.
pub const SLOTS_MAX: usize = 2_048;
/// Most functions one site declares (docs/07 section 7.9.18).
pub const FUNCTIONS_MAX: usize = 2_048;
/// Largest uses or sessions a site may require before the rules propose a kind.
pub const THRESHOLD_MAX: u32 = 10_000;
/// Largest number of questions a site may allow the learning agent each day.
pub const AGENT_DAILY_MAX: u32 = 100_000;
/// Longest position key, in bytes.
pub const KEY_MAX: usize = 256;
/// Shortest and longest kind id, in bytes (lower-case ASCII letters).
const CLASS_ID_MIN: usize = 3;
const CLASS_ID_MAX: usize = 24;
/// Longest display name and description, in characters.
pub(crate) const NAME_MAX: usize = 32;
pub(crate) const DESCRIPTION_MAX: usize = 200;

/// One kind of object (the object-map design note, section 1, "类别").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectClass {
    /// Stable id, for example `doctor`. Renaming changes only `name`.
    pub id: String,
    /// The name the console shows, for example `医生`.
    pub name: String,
    /// What the kind is, in the words an administrator uses.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Where a confirmed entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotSource {
    /// Declared by an administrator.
    Admin,
    /// Proposed by the rules and confirmed by an administrator.
    Rule,
    /// Proposed by the learning agent and confirmed by an administrator.
    Agent,
}

/// The identity a response position states about the session (docs/01 section 1.2): the
/// origin's own word, in a response, about who the session is. A request never states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    /// The user the session is logged in as. The gateway keeps a keyed hash of the id only.
    User,
    /// The organization or tenant the session acts for. The gateway keeps a keyed hash only.
    Org,
    /// The role the session holds, such as `admin`. The gateway keeps its label, see [`role_label`].
    Role,
}

/// Whose objects a response position shows (the tier of the object-map learning, docs/07
/// section 7.9.16). `self` holds the current user's own objects, `org` the objects of the
/// user's organisation, `admin` the objects only admin sessions get back, and `public`
/// objects many users see alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// The current user's own objects, written `self`.
    #[serde(rename = "self")]
    Own,
    /// The objects of the current user's organisation.
    Org,
    /// Objects that only admin sessions get back.
    Admin,
    /// Objects many users see alike.
    Public,
}

/// How sure the learning is of a tier or of an acceptance. The judge tightens only on
/// `high`; `medium` is proposed to an administrator and changes no decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reliability {
    /// Too little evidence or too little agreement. Never proposed.
    Low,
    /// Enough evidence to propose; not enough for the judge to tighten.
    Medium,
    /// Enough evidence, and nearly every unit agrees.
    High,
}

/// One confirmed position and the kind of object it carries.
///
/// The learning may add a judgement to an entry: a response position may carry a `tier`,
/// and a request position may carry `accepts_public`. `reliability` qualifies the one that
/// is there. An absent judgement is unknown, and the judge then behaves as it did before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSlot {
    /// The position key, `METHOD /route/{id} location`.
    pub key: String,
    /// The id of a declared kind.
    pub class: String,
    /// Where the entry came from.
    pub source: SlotSource,
    /// Paused: the entry stays, so the position keeps its kind and the learning task
    /// knows it, but the judge does not use the kind. The position is judged by its name
    /// until an administrator writes the entry back without the flag. Absent means not
    /// paused. A paused entry keeps its judgement too, and the judge does not use that either.
    #[serde(default, skip_serializing_if = "is_false")]
    pub paused: bool,
    /// The identity this response position states about the session, when it does: `user`,
    /// `org` or `role`. Absent for an ordinary position. Only responses are read for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityRole>,
    /// For a response position: whose objects it shows. Absent means unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// For a request position: whether normal traffic sends values from public positions
    /// here. `false` means it rarely does. Absent means unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts_public: Option<bool>,
    /// How sure the learning is of `tier` or `accepts_public`. Absent counts as low.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<Reliability>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

/// One function of the site, such as `POST /api/admin/export` (docs/07 section 7.9.18). An entry
/// without a `tier` says only that the site has the function. A `tier` of `admin`, with `reliability`
/// `high`, says that only administrator sessions use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectFunction {
    /// The method and the route template, separated by one space: `GET /api/patients/{id}`.
    pub key: String,
    /// Where the entry came from.
    pub source: SlotSource,
    /// Whose function it is. Only `admin` is accepted; the map refuses any other tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// How sure the learning is of the `tier`. Only written with a `tier`; absent counts as low.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<Reliability>,
}

/// The learning settings of a site (`objects.learning`, console design 3.5). A key
/// that is absent means its default. Settings that all hold their defaults are not
/// written back, so a configuration that does not change them keeps no `learning`
/// key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LearningSettings {
    /// Off: the learning pass reads nothing for the site, and only hand-declared
    /// and confirmed positions apply.
    pub auto_learn: bool,
    /// Tightening changes apply on their own; off sends them to the proposal queue
    /// too. Stored now, acted on once the judge reads the learned states.
    pub auto_tighten: bool,
    /// Confirmed positions that turn abnormal are paused on their own. Stored now,
    /// acted on once the judge reads the learned states.
    pub auto_pause: bool,
    /// How much evidence a position needs before the rules may propose a kind.
    pub thresholds: LearningThresholds,
    /// The learning agent's settings.
    pub agent: LearningAgent,
}

/// The evidence a position needs before the rules may propose a kind for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LearningThresholds {
    /// Requests that used the position (votes), at least 1.
    pub uses: u32,
    /// Distinct sessions that used it, at least 1.
    pub sessions: u32,
}

/// The learning agent's settings. The agent answers the positions the rules cannot decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LearningAgent {
    /// Ask the agent about positions the rules cannot decide. The control plane asks only
    /// when an agent model is configured, so a site may switch it on before then and wait.
    pub enabled: bool,
    /// Most questions the agent may be asked in a day.
    pub daily_limit: u32,
}

impl Default for LearningSettings {
    fn default() -> Self {
        Self {
            auto_learn: true,
            auto_tighten: true,
            auto_pause: true,
            thresholds: LearningThresholds::default(),
            agent: LearningAgent::default(),
        }
    }
}

impl LearningSettings {
    /// Whether every setting holds its default, in which case nothing is written.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl Default for LearningThresholds {
    fn default() -> Self {
        Self {
            uses: VOTES_MIN,
            sessions: SESSIONS_MIN,
        }
    }
}

impl Default for LearningAgent {
    fn default() -> Self {
        Self {
            enabled: false,
            daily_limit: 200,
        }
    }
}

/// The `objects` section as written. [`ObjectMap::try_from`] validates it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectMapDto {
    /// Declared kinds, at most [`CLASSES_MAX`].
    #[serde(default)]
    pub classes: Vec<ObjectClass>,
    /// Confirmed positions, at most [`SLOTS_MAX`].
    #[serde(default)]
    pub slots: Vec<ObjectSlot>,
    /// Functions of the site, at most [`FUNCTIONS_MAX`]. Absent or empty is not written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<ObjectFunction>,
    /// Whether the judge asks Jev about a request whose function the table does not list
    /// (`objects.ask_unknown_functions`, docs/07 section 7.9.18). Needs `functions`. Absent or false
    /// is not written.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ask_unknown_functions: bool,
    /// Learning settings, at `objects.learning`. Absent or default settings are not written.
    #[serde(default, skip_serializing_if = "LearningSettings::is_default")]
    pub learning: LearningSettings,
}

/// A validated object map. Lookups go through [`ObjectMap::class_of`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ObjectMapDto", into = "ObjectMapDto")]
pub struct ObjectMap {
    classes: Vec<ObjectClass>,
    slots: Vec<ObjectSlot>,
    /// The functions, in the order they were written.
    functions: Vec<ObjectFunction>,
    /// Whether the judge asks Jev about functions the table does not list.
    ask_unknown_functions: bool,
    /// Whether the judge reads the function table at all. Worked out once, when the map is validated.
    #[serde(skip)]
    guards: bool,
    /// The learning settings. The default when the site sets none.
    learning: LearningSettings,
    /// Position key to its place in `slots`, built once when the map is validated.
    #[serde(skip)]
    index: BTreeMap<String, usize>,
    /// The templates of the functions and of the positions, grouped for the lookups.
    #[serde(skip)]
    shapes: Shapes,
}

impl ObjectMap {
    /// Whether the site declares nothing and keeps the default learning settings
    /// (the common case before learning).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
            && self.slots.is_empty()
            && self.functions.is_empty()
            && !self.ask_unknown_functions
            && self.learning.is_default()
    }

    /// The learning settings; the defaults when the site sets none.
    #[must_use]
    pub fn learning(&self) -> &LearningSettings {
        &self.learning
    }

    /// The declared kinds, in the order they were written.
    #[must_use]
    pub fn classes(&self) -> &[ObjectClass] {
        &self.classes
    }

    /// The confirmed positions, in the order they were written.
    #[must_use]
    pub fn slots(&self) -> &[ObjectSlot] {
        &self.slots
    }

    /// The kind of object a position carries, when the map confirms one and does not
    /// pause it. The judge and the learning task compare kinds through this.
    #[must_use]
    pub fn class_of(&self, key: &str) -> Option<&str> {
        self.slot(key)
            .filter(|slot| !slot.paused)
            .map(|slot| slot.class.as_str())
    }

    /// The kind an entry declares for a position, paused or not.
    #[must_use]
    pub fn declared_class_of(&self, key: &str) -> Option<&str> {
        self.slot(key).map(|slot| slot.class.as_str())
    }

    /// Whether the map has an entry for the position and that entry is paused.
    #[must_use]
    pub fn is_paused(&self, key: &str) -> bool {
        self.slot(key).is_some_and(|slot| slot.paused)
    }

    /// The identity a response position states about the session, when the map declares one and
    /// does not pause the entry. The judge reads it from responses only.
    #[must_use]
    pub fn identity_of(&self, key: &str) -> Option<IdentityRole> {
        self.slot(key)
            .filter(|slot| !slot.paused)
            .and_then(|slot| slot.identity)
    }

    /// Whether the site has a user identity position: an entry that states the user and is not paused.
    /// Only such a site asks an identity response to declare the user before it recognizes a credential
    /// (docs/01 section 1.2).
    #[must_use]
    pub fn declares_user_identity(&self) -> bool {
        self.slots()
            .iter()
            .any(|slot| !slot.paused && slot.identity == Some(IdentityRole::User))
    }

    /// The map with the entries of `keys` paused. A key the map does not declare, and an
    /// entry already paused, change nothing. The index stays valid: keys and places do not move.
    #[must_use]
    pub fn with_paused(mut self, keys: &[String]) -> Self {
        for slot in &mut self.slots {
            if keys.contains(&slot.key) {
                slot.paused = true;
            }
        }
        self
    }

    /// The map with `key` set to `class` from `source`, and not paused. The entry the map has
    /// for the key is replaced, paused or not, but its judgement (`tier`, `accepts_public`,
    /// `reliability`) and the identity it states are kept: confirming a kind does not discard
    /// what the learning judged, nor who the response says the session is.
    /// A key the map does not declare is appended, so the index stays valid.
    #[must_use]
    pub fn with_entry(mut self, key: &str, class: &str, source: SlotSource) -> Self {
        if let Some(&place) = self.index.get(key) {
            if let Some(slot) = self.slots.get_mut(place) {
                class.clone_into(&mut slot.class);
                slot.source = source;
                slot.paused = false;
            }
        } else {
            let place = self.slots.len();
            self.index.insert(key.to_owned(), place);
            self.shapes.add_position(place, key);
            self.slots.push(ObjectSlot {
                key: key.to_owned(),
                class: class.to_owned(),
                source,
                paused: false,
                tier: None,
                accepts_public: None,
                reliability: None,
                identity: None,
            });
        }
        self
    }

    /// The map with the acceptance judgement of a request position set: whether normal traffic
    /// sends public sources to it, and how sure the learning is. The entry keeps its kind and
    /// its paused flag. `None` when the map does not declare the key, or when the entry carries
    /// a `tier`, since an entry carries one judgement at most.
    #[must_use]
    pub fn with_accepts_public(
        mut self,
        key: &str,
        accepts_public: bool,
        reliability: Reliability,
    ) -> Option<Self> {
        let place = *self.index.get(key)?;
        let slot = self.slots.get_mut(place)?;
        if slot.tier.is_some() {
            return None;
        }
        slot.accepts_public = Some(accepts_public);
        slot.reliability = Some(reliability);
        Some(self)
    }

    /// The map with the tier judgement of a response position set: whose objects it shows, and how sure
    /// the learning is. The entry keeps its kind, its identity and its paused flag. `None` when the map
    /// does not declare the key, or when the entry carries an `accepts_public`, since an entry carries one
    /// judgement at most.
    #[must_use]
    pub fn with_tier(mut self, key: &str, tier: Tier, reliability: Reliability) -> Option<Self> {
        let place = *self.index.get(key)?;
        let slot = self.slots.get_mut(place)?;
        if slot.accepts_public.is_some() {
            return None;
        }
        slot.tier = Some(tier);
        slot.reliability = Some(reliability);
        Some(self)
    }

    /// The tier a response position is confirmed with, when the map confirms one and does
    /// not pause the entry. The judge and the acceptance learning read tiers through this.
    #[must_use]
    pub fn tier_of(&self, key: &str) -> Option<Tier> {
        self.live(key).and_then(|slot| slot.tier)
    }

    /// Whether a request position is confirmed to accept public sources: `Some(false)` when
    /// normal traffic rarely sends them. Only confirmed, unpaused entries answer.
    #[must_use]
    pub fn accepts_public_of(&self, key: &str) -> Option<bool> {
        self.live(key).and_then(|slot| slot.accepts_public)
    }

    /// How sure the learning is of the judgement of a position, when the map confirms one and
    /// does not pause the entry.
    #[must_use]
    pub fn reliability_of(&self, key: &str) -> Option<Reliability> {
        self.live(key).and_then(|slot| slot.reliability)
    }

    /// The tier of a response position and how sure the map is of it: an absent reliability is
    /// low (docs/07 section 7.9.16). `None` when the map gives no tier there.
    #[must_use]
    pub fn tier_judgement_of(&self, key: &str) -> Option<(Tier, Reliability)> {
        Some((
            self.tier_of(key)?,
            self.reliability_of(key).unwrap_or(Reliability::Low),
        ))
    }

    /// Whether the map is sure that a request position takes no public source: `accepts_public`
    /// is false and its reliability high (docs/07 section 7.4.7).
    #[must_use]
    pub fn closed_to_public(&self, key: &str) -> bool {
        self.accepts_public_of(key) == Some(false)
            && self.reliability_of(key) == Some(Reliability::High)
    }

    /// Whether a live entry says anything about public sources on a request position. Only such
    /// a site is judged by where its request values sit (docs/07 section 7.4.7).
    #[must_use]
    pub fn judges_public_access(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| !slot.paused && slot.accepts_public.is_some())
    }

    /// The key of the position that governs a request value: `method`, the route `template` the
    /// judge keys it by, and its location `at`. An entry with exactly that key governs it.
    /// On a site that judges public access, an entry whose route template covers `template`
    /// governs it too, where its `{id}` segments stand for any one segment: a declared numeric id
    /// then also governs a slug id (`PT-7004`) or a segment with a `;` parameter at the same place.
    /// Among covering entries the one with the most literal segments wins, then a closed one.
    /// Paused entries count, so a paused position still places its values. Elsewhere only the
    /// exact key governs, as it always did, so a site without public access is judged as before.
    #[must_use]
    pub fn request_key(&self, method: &str, template: &str, at: &str) -> Option<&str> {
        let exact = format!("{method} {template} {at}");
        if let Some((key, _)) = self.index.get_key_value(exact.as_str()) {
            return Some(key.as_str());
        }
        if !self.judges_public_access() {
            return None;
        }
        self.slots
            .iter()
            .filter_map(|slot| {
                let (declared_method, rest) = slot.key.split_once(' ')?;
                let (declared, location) = rest.rsplit_once(' ')?;
                if declared_method != method || location != at {
                    return None;
                }
                let literal = template_covers(declared, template)?;
                Some((
                    (literal, self.closed_to_public(&slot.key)),
                    slot.key.as_str(),
                ))
            })
            .max_by_key(|(rank, _)| *rank)
            .map(|(_, key)| key)
    }

    /// The functions, in the order they were written.
    #[must_use]
    pub fn functions(&self) -> &[ObjectFunction] {
        &self.functions
    }

    /// Whether the judge asks Jev about a request whose function the table does not list
    /// (docs/07 section 7.9.18).
    #[must_use]
    pub fn asks_unknown_functions(&self) -> bool {
        self.ask_unknown_functions
    }

    /// Whether the judge reads the function table for this site at all: it asks about unknown
    /// functions, or the table holds an administrator's function the map is sure of. A site for
    /// which this is false is judged exactly as before the table existed (docs/07 section 7.9.18).
    #[must_use]
    pub fn guards_functions(&self) -> bool {
        self.guards
    }

    /// The function that governs a request: `method`, and the route `template` the judge keys it
    /// by (docs/07 section 7.9.18). `HEAD` is looked up as `GET`. `OPTIONS` is a preflight, which
    /// carries no credential, so it names no function. Among the functions whose template covers
    /// `template`, the one with the most literal segments wins; then the one with more `{id}`
    /// segments, which is the narrower placeholder; then the stricter one, which is an `admin` tier
    /// with `high` reliability; then the one written first.
    #[must_use]
    pub fn function_of(&self, method: &str, template: &str) -> Option<&ObjectFunction> {
        if method == "OPTIONS" {
            return None;
        }
        let request: Vec<&str> = template.split('/').collect();
        self.shapes
            .functions
            .get(head_as_get(method))?
            .get(&request.len())?
            .iter()
            .filter_map(|declared| {
                let (literal, ids) = covers(&declared.segments, &request)?;
                let function = self.functions.get(declared.place)?;
                let rank = (
                    literal,
                    ids,
                    admin_and_high(function),
                    Reverse(declared.place),
                );
                Some((rank, function))
            })
            .max_by_key(|(rank, _)| *rank)
            .map(|(_, function)| function)
    }

    /// Whether the function that governs a request is an administrator's that the map is sure of:
    /// `tier` `admin` with `reliability` `high`. A less sure entry tightens nothing.
    #[must_use]
    pub fn admin_only(&self, method: &str, template: &str) -> bool {
        self.function_of(method, template)
            .is_some_and(admin_and_high)
    }

    /// Whether the site knows the function of a request (docs/07 section 7.9.18). It does when a
    /// function covers the request, or when a declared position lies on the same route: the position
    /// already says that the route exists. A preflight is known when its route is known for any method.
    #[must_use]
    pub fn knows_function(&self, method: &str, template: &str) -> bool {
        let request: Vec<&str> = template.split('/').collect();
        if method == "OPTIONS" {
            return covers_any_method(&self.shapes.functions, &request)
                || covers_any_method(&self.shapes.positions, &request);
        }
        self.function_of(method, template).is_some()
            || covers_for_method(&self.shapes.positions, head_as_get(method), &request)
    }

    /// The entry of a position when it is not paused.
    fn live(&self, key: &str) -> Option<&ObjectSlot> {
        self.slot(key).filter(|slot| !slot.paused)
    }

    /// The entry of a position, paused or not.
    fn slot(&self, key: &str) -> Option<&ObjectSlot> {
        self.index.get(key).and_then(|&place| self.slots.get(place))
    }
}

/// Why an object map is refused: the part that is wrong, and the reason when the rules
/// name one. The text the API sends names the entry and never echoes a configured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectsIssue {
    /// Where the map is wrong.
    pub place: ObjectsPlace,
    /// Why, for the refusals the console can explain. `None` for the others.
    pub reason: Option<ObjectsReason>,
}

impl ObjectsIssue {
    /// The part the refusal is about, as the API names it: `objects.slots[3]`, counted
    /// from 0 in the order the entries were written.
    #[must_use]
    pub fn field(&self) -> String {
        match self.place {
            ObjectsPlace::Section => "objects".to_owned(),
            ObjectsPlace::Learning => "objects.learning".to_owned(),
            ObjectsPlace::Classes => "objects.classes".to_owned(),
            ObjectsPlace::Class(index) => format!("objects.classes[{index}]"),
            ObjectsPlace::Slots => "objects.slots".to_owned(),
            ObjectsPlace::Slot(index) => format!("objects.slots[{index}]"),
            ObjectsPlace::Functions => "objects.functions".to_owned(),
            ObjectsPlace::Function(index) => format!("objects.functions[{index}]"),
            ObjectsPlace::AskUnknownFunctions => "objects.ask_unknown_functions".to_owned(),
        }
    }
}

/// The part of the `objects` section a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectsPlace {
    /// The section itself: it is not an object, or it holds a field it does not know.
    Section,
    /// `objects.learning`.
    Learning,
    /// The list of kinds, `objects.classes`.
    Classes,
    /// One kind, `objects.classes[n]`.
    Class(usize),
    /// The list of confirmed positions, `objects.slots`.
    Slots,
    /// One confirmed position, `objects.slots[n]`.
    Slot(usize),
    /// The list of functions, `objects.functions`.
    Functions,
    /// One function, `objects.functions[n]`.
    Function(usize),
    /// The switch `objects.ask_unknown_functions`.
    AskUnknownFunctions,
}

/// The reasons an object map entry is refused, as their stable codes name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectsReason {
    /// A position names a kind the section does not declare.
    ClassUnknown,
    /// A kind id or a position key is written twice.
    DuplicateKey,
    /// A position key is not `METHOD /template location`, or is longer than `KEY_MAX`.
    KeyInvalid,
    /// More kinds or positions than the map allows.
    TooMany,
    /// A kind id is not lower-case ASCII letters, or not 3 to 24 of them.
    ClassIdInvalid,
    /// A position carries both a `tier` (a response judgement) and `accepts_public` (a request
    /// judgement). A position is one or the other.
    JudgementConflict,
    /// A `reliability` with neither a `tier` nor `accepts_public` to qualify.
    ReliabilityWithoutJudgement,
    /// A function's `tier` is something other than `admin`. A function is an administrator's, or open to all.
    FunctionTierUnsupported,
    /// The switch is on, but the site lists no function for the judge to ask about.
    AskWithoutFunctions,
}

impl ObjectsReason {
    /// The stable code of the reason, as the API sends it in `reason`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::ClassUnknown => "class_unknown",
            Self::DuplicateKey => "duplicate_key",
            Self::KeyInvalid => "key_invalid",
            Self::TooMany => "too_many",
            Self::ClassIdInvalid => "class_id_invalid",
            Self::JudgementConflict => "judgement_conflict",
            Self::ReliabilityWithoutJudgement => "reliability_without_judgement",
            Self::FunctionTierUnsupported => "function_tier_unsupported",
            Self::AskWithoutFunctions => "ask_without_functions",
        }
    }
}

fn refused(place: ObjectsPlace, reason: Option<ObjectsReason>) -> ConfigError {
    ConfigError::Objects(ObjectsIssue { place, reason })
}

impl TryFrom<ObjectMapDto> for ObjectMap {
    type Error = ConfigError;

    fn try_from(dto: ObjectMapDto) -> Result<Self, ConfigError> {
        if dto.classes.len() > CLASSES_MAX {
            return Err(refused(ObjectsPlace::Classes, Some(ObjectsReason::TooMany)));
        }
        if dto.slots.len() > SLOTS_MAX {
            return Err(refused(ObjectsPlace::Slots, Some(ObjectsReason::TooMany)));
        }
        if dto.functions.len() > FUNCTIONS_MAX {
            return Err(refused(
                ObjectsPlace::Functions,
                Some(ObjectsReason::TooMany),
            ));
        }
        if !valid_learning(&dto.learning) {
            return Err(refused(ObjectsPlace::Learning, None));
        }
        let mut ids = BTreeMap::new();
        for (at, class) in dto.classes.iter().enumerate() {
            let place = ObjectsPlace::Class(at);
            if !valid_class_id(&class.id) {
                return Err(refused(place, Some(ObjectsReason::ClassIdInvalid)));
            }
            if class.name.is_empty()
                || class.name.chars().count() > NAME_MAX
                || class.description.chars().count() > DESCRIPTION_MAX
            {
                return Err(refused(place, None));
            }
            if ids.insert(class.id.as_str(), ()).is_some() {
                return Err(refused(place, Some(ObjectsReason::DuplicateKey)));
            }
        }
        let mut index = BTreeMap::new();
        let mut shapes = Shapes::default();
        for (at, slot) in dto.slots.iter().enumerate() {
            let place = ObjectsPlace::Slot(at);
            if !valid_key(&slot.key) {
                return Err(refused(place, Some(ObjectsReason::KeyInvalid)));
            }
            if !ids.contains_key(slot.class.as_str()) {
                return Err(refused(place, Some(ObjectsReason::ClassUnknown)));
            }
            if slot.tier.is_some() && slot.accepts_public.is_some() {
                return Err(refused(place, Some(ObjectsReason::JudgementConflict)));
            }
            if slot.reliability.is_some() && slot.tier.is_none() && slot.accepts_public.is_none() {
                return Err(refused(
                    place,
                    Some(ObjectsReason::ReliabilityWithoutJudgement),
                ));
            }
            if index.insert(slot.key.clone(), at).is_some() {
                return Err(refused(place, Some(ObjectsReason::DuplicateKey)));
            }
            shapes.add_position(at, &slot.key);
        }
        check_functions(&dto.functions, &mut shapes)?;
        if dto.ask_unknown_functions && dto.functions.is_empty() {
            return Err(refused(
                ObjectsPlace::AskUnknownFunctions,
                Some(ObjectsReason::AskWithoutFunctions),
            ));
        }
        let guards = dto.ask_unknown_functions || dto.functions.iter().any(admin_and_high);
        Ok(Self {
            classes: dto.classes,
            slots: dto.slots,
            functions: dto.functions,
            ask_unknown_functions: dto.ask_unknown_functions,
            guards,
            learning: dto.learning,
            index,
            shapes,
        })
    }
}

impl From<ObjectMap> for ObjectMapDto {
    fn from(map: ObjectMap) -> Self {
        Self {
            classes: map.classes,
            slots: map.slots,
            functions: map.functions,
            ask_unknown_functions: map.ask_unknown_functions,
            learning: map.learning,
        }
    }
}

/// The learning settings a site may hold. The thresholds are at least one and at most
/// [`THRESHOLD_MAX`], the agent's daily limit at most [`AGENT_DAILY_MAX`]. Whether the
/// agent has a model to ask is the control plane's to say, so a site may switch it on.
fn valid_learning(learning: &LearningSettings) -> bool {
    (1..=THRESHOLD_MAX).contains(&learning.thresholds.uses)
        && (1..=THRESHOLD_MAX).contains(&learning.thresholds.sessions)
        && learning.agent.daily_limit <= AGENT_DAILY_MAX
}

/// `lower-case` letters only, 3 to 24 bytes, as the kind rules of the
/// field-kind declarations use.
pub(crate) fn valid_class_id(id: &str) -> bool {
    (CLASS_ID_MIN..=CLASS_ID_MAX).contains(&id.len())
        && id.bytes().all(|byte| byte.is_ascii_lowercase())
}

/// The role label that makes a session an administrator for the judge (docs/07 section 7.4.7): the
/// label the site's `role` identity position declares, as [`role_label`] keeps it.
pub const ADMIN_ROLE: &str = "admin";

/// Whether a response with this tier, and how sure the map is of it, proves a right to the object
/// it shows, at a request position that is `closed` to public sources or not, for a session that
/// is `admin` or not (docs/07 section 7.4.7). A response the map does not classify proves it, as
/// every response did before tiers, and so do an own (`self`) response, which shows the session its
/// own record, and an org response. A public response the map is sure of proves it unless the
/// position is closed; a public response the map is not sure of proves it, as before tiers. An
/// administrator's listing proves a value to an administrator session, as an ordinary response does,
/// and to no other session: a role is not a reason to allow, so an object an administrator never saw
/// is still blocked. A self label also keeps a value from being an attempt; that is judged in the
/// judge's `tiers` module, not here.
#[must_use]
pub fn tier_proves(tier: Option<(Tier, Reliability)>, closed: bool, admin: bool) -> bool {
    match tier {
        Some((Tier::Admin, _)) => admin,
        Some((Tier::Public, Reliability::High)) => !closed,
        None | Some((Tier::Own | Tier::Org | Tier::Public, _)) => true,
    }
}

/// Whether the declared route template `declared` covers `template`: the same segments, except
/// that a `{id}` segment of `declared` stands for any one non-empty segment of `template`. The
/// result counts the segments that agree literally, so that a more specific entry can win.
fn template_covers(declared: &str, template: &str) -> Option<usize> {
    let declared: Vec<&str> = declared.split('/').collect();
    let template: Vec<&str> = template.split('/').collect();
    if declared.len() != template.len() {
        return None;
    }
    let mut literal = 0;
    for (name, actual) in declared.iter().zip(&template) {
        if *name == "{id}" {
            if actual.is_empty() {
                return None;
            }
        } else if name == actual {
            literal += 1;
        } else {
            return None;
        }
    }
    Some(literal)
}

/// The method a lookup reads a request by: `HEAD` is a `GET` without its body.
fn head_as_get(method: &str) -> &str {
    if method == "HEAD" { "GET" } else { method }
}

/// Whether a function is an administrator's, and the map is sure of it.
fn admin_and_high(function: &ObjectFunction) -> bool {
    function.tier == Some(Tier::Admin) && function.reliability == Some(Reliability::High)
}

/// The declared templates of one list, by method and then by number of segments.
type Groups = BTreeMap<String, BTreeMap<usize, Vec<Declared>>>;

/// One declared route template, split into its segments, and the place of its entry in its list.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Declared {
    place: usize,
    segments: Vec<String>,
}

/// The route templates of the functions and of the positions, grouped by method and by number of
/// segments, and split once when the map is built. A lookup reads only the group of its own method
/// and length (docs/07 section 7.9.18).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Shapes {
    functions: Groups,
    positions: Groups,
}

impl Shapes {
    fn add_function(&mut self, place: usize, key: &str) {
        add_template(&mut self.functions, place, key);
    }

    fn add_position(&mut self, place: usize, key: &str) {
        // Placement reads a position by `{id}` alone (`template_covers`). A `{name}` in a position
        // covers no route here, as it never did before the placeholder existed.
        let names_a_segment = key
            .split(' ')
            .nth(1)
            .is_some_and(|template| template.split('/').any(|segment| segment == "{name}"));
        if !names_a_segment {
            add_template(&mut self.positions, place, key);
        }
    }
}

/// Adds the template of `key`, either `METHOD /template` or `METHOD /template location`, to its
/// group. A key without a template is not added: no request could be looked up to it.
fn add_template(groups: &mut Groups, place: usize, key: &str) {
    let mut parts = key.split(' ');
    let (Some(method), Some(template)) = (parts.next(), parts.next()) else {
        return;
    };
    let segments: Vec<String> = template.split('/').map(str::to_owned).collect();
    groups
        .entry(method.to_owned())
        .or_default()
        .entry(segments.len())
        .or_default()
        .push(Declared { place, segments });
}

/// Whether a template of any method in `groups` covers the request template.
fn covers_any_method(groups: &Groups, request: &[&str]) -> bool {
    groups.values().any(|by_count| covers_in(by_count, request))
}

/// Whether a template of `method` in `groups` covers the request template.
fn covers_for_method(groups: &Groups, method: &str, request: &[&str]) -> bool {
    groups
        .get(method)
        .is_some_and(|by_count| covers_in(by_count, request))
}

/// Whether one of the templates with as many segments as the request covers it.
fn covers_in(by_count: &BTreeMap<usize, Vec<Declared>>, request: &[&str]) -> bool {
    by_count.get(&request.len()).is_some_and(|group| {
        group
            .iter()
            .any(|declared| covers(&declared.segments, request).is_some())
    })
}

/// Whether a function template covers a request template, and how (docs/07 section 7.9.18): the
/// number of segments that agree literally, and the number of `{id}` segments. A request segment
/// loses its `;` parameters first. A `{name}` segment of the template covers any segment that is not
/// empty without them. An `{id}` segment covers a value only: a segment that is empty without them,
/// or a route word (`is_plain_word`), is not covered, and neither is the request's own `{name}`
/// placeholder. A request's own `{id}` is covered by both. Any other segment agrees with the request
/// segment without its `;` parameters, ignoring ASCII case; a segment that is empty after that agrees
/// with no literal segment. The comparison is blind to case and to `;` parameters on purpose: an
/// origin that ignores either serves the same function under those spellings.
fn covers(declared: &[String], request: &[&str]) -> Option<(usize, usize)> {
    if declared.len() != request.len() {
        return None;
    }
    let mut literal = 0;
    let mut ids = 0;
    for (name, actual) in declared.iter().zip(request) {
        let bare = actual.split_once(';').map_or(*actual, |(bare, _)| bare);
        match name.as_str() {
            "{id}" => {
                if bare.is_empty() || bare == "{name}" || is_plain_word(bare) {
                    return None;
                }
                ids += 1;
            }
            "{name}" => {
                if bare.is_empty() {
                    return None;
                }
            }
            _ => {
                // The empty segment before the first `/` is empty to begin with, and agrees with the
                // empty segment of the template. A segment that is empty only once its `;` parameters
                // are removed agrees with no literal segment.
                let agrees = if actual.is_empty() {
                    name.is_empty()
                } else {
                    !bare.is_empty() && bare.eq_ignore_ascii_case(name)
                };
                if !agrees {
                    return None;
                }
                literal += 1;
            }
        }
    }
    Some((literal, ids))
}

/// `METHOD /template` for a function key (docs/07 section 7.9.18): two parts split by one space, a
/// method of 3 to 7 upper-case ASCII letters other than `HEAD` and `OPTIONS`, and a template in the
/// spelling the judge keys positions by. A segment that carries a brace is `{id}` or `{name}` and
/// nothing else, and no segment carries a `;`: a lookup removes those from the request, so such a
/// segment could never match.
fn valid_function_key(key: &str) -> bool {
    let mut parts = key.split(' ');
    let (Some(method), Some(template), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    key.len() <= KEY_MAX
        && (3..=7).contains(&method.len())
        && method.bytes().all(|byte| byte.is_ascii_uppercase())
        && !matches!(method, "HEAD" | "OPTIONS")
        && template.starts_with('/')
        && !template.contains(['?', '#', ';'])
        && !template.bytes().any(|byte| byte.is_ascii_control())
        && canonical_path(template).as_deref() == Some(template)
        && position_template(template) == template
        && template
            .split('/')
            .all(|segment| !segment.contains(['{', '}']) || matches!(segment, "{id}" | "{name}"))
}

/// Checks the functions of a map in the order they were written, and adds each to the shapes the
/// lookups read. A refusal names the function that is wrong.
fn check_functions(functions: &[ObjectFunction], shapes: &mut Shapes) -> Result<(), ConfigError> {
    let mut keys = BTreeSet::new();
    for (at, function) in functions.iter().enumerate() {
        let place = ObjectsPlace::Function(at);
        if !valid_function_key(&function.key) {
            return Err(refused(place, Some(ObjectsReason::KeyInvalid)));
        }
        if function.tier.is_some_and(|tier| tier != Tier::Admin) {
            return Err(refused(place, Some(ObjectsReason::FunctionTierUnsupported)));
        }
        if function.reliability.is_some() && function.tier.is_none() {
            return Err(refused(
                place,
                Some(ObjectsReason::ReliabilityWithoutJudgement),
            ));
        }
        // Two keys that differ only in the case of the template are one route to a lookup.
        if !keys.insert(function.key.to_ascii_lowercase()) {
            return Err(refused(place, Some(ObjectsReason::DuplicateKey)));
        }
        shapes.add_function(at, &function.key);
    }
    Ok(())
}

/// `METHOD /template location`: an upper-case method, a path template that starts with `/`,
/// carries no query or fragment, and is in the spelling the judge keys positions by
/// ([`canonical_path`]), and a location with no spaces. The key is only compared, never routed,
/// so the checks are about shape: a key that cannot be produced by the judge is refused.
fn valid_key(key: &str) -> bool {
    let mut parts = key.split(' ');
    let (Some(method), Some(template), Some(location), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    key.len() <= KEY_MAX
        && (3..=7).contains(&method.len())
        && method.bytes().all(|byte| byte.is_ascii_uppercase())
        && template.starts_with('/')
        && !template.contains(['?', '#'])
        && !template.bytes().any(|byte| byte.is_ascii_control())
        && canonical_path(template).as_deref() == Some(template)
        && !location.is_empty()
        && location.len() <= 128
        && location.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Longest role label the gateway keeps, in bytes.
pub const ROLE_MAX: usize = 32;

/// The role label a response names, or `None` when the value is not one. A role is a short
/// category such as `admin`, so its label is the trimmed, lower-case text: 1 to 32 ASCII
/// letters, digits, `_`, `-`, `.` or `:`. Any other value names no role, and a value that may
/// be a name or an id is never kept as text.
#[must_use]
pub fn role_label(value: &str) -> Option<String> {
    let role = value.trim().to_ascii_lowercase();
    let fits = !role.is_empty()
        && role.len() <= ROLE_MAX
        && role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));
    fits.then_some(role)
}

#[cfg(test)]
mod judgement_tests {
    use super::*;

    const JUDGED: &str = r#"{
        "classes": [{"id": "patient", "name": "患者"}],
        "slots": [
            {"key": "GET /api/search [].id", "class": "patient", "source": "rule",
             "tier": "public", "reliability": "high"},
            {"key": "DELETE /api/patients/{id} path[1]", "class": "patient", "source": "admin",
             "accepts_public": false, "reliability": "medium"},
            {"key": "GET /api/patients [].id", "class": "patient", "source": "admin", "tier": "self"}
        ]
    }"#;

    fn map(json: &str) -> ObjectMap {
        let dto: ObjectMapDto = serde_json::from_str(json).expect("the section parses");
        ObjectMap::try_from(dto).expect("the map is valid")
    }

    /// The reason a section is refused, when the rules name one.
    fn refusal(json: &str) -> Option<ObjectsReason> {
        let dto: ObjectMapDto = serde_json::from_str(json).expect("the section parses");
        match ObjectMap::try_from(dto) {
            Err(ConfigError::Objects(issue)) => issue.reason,
            _ => None,
        }
    }

    #[test]
    fn judgements_are_read_and_written_and_absent_when_unknown() {
        let judged = map(JUDGED);
        assert_eq!(judged.tier_of("GET /api/search [].id"), Some(Tier::Public));
        assert_eq!(
            judged.reliability_of("GET /api/search [].id"),
            Some(Reliability::High)
        );
        assert_eq!(
            judged.accepts_public_of("DELETE /api/patients/{id} path[1]"),
            Some(false)
        );
        assert_eq!(
            judged.reliability_of("DELETE /api/patients/{id} path[1]"),
            Some(Reliability::Medium)
        );
        assert_eq!(judged.tier_of("GET /api/patients [].id"), Some(Tier::Own));
        assert_eq!(judged.reliability_of("GET /api/patients [].id"), None);
        assert_eq!(judged.tier_of("GET /api/unknown [].id"), None);

        let written = serde_json::to_value(&judged).expect("the map writes");
        let slots = written["slots"].as_array().expect("the slots are an array");
        assert_eq!(slots[0]["tier"], "public");
        assert_eq!(slots[0]["reliability"], "high");
        assert_eq!(slots[1]["accepts_public"], false);
        assert_eq!(slots[1]["reliability"], "medium");
        assert_eq!(slots[2]["tier"], "self");
        assert!(slots[2].get("reliability").is_none());
        assert!(slots[2].get("accepts_public").is_none());
        assert!(slots[2].get("paused").is_none());
    }

    #[test]
    fn a_position_names_one_judgement_and_a_reliability_needs_one() {
        let both = r#"{"classes": [{"id": "patient", "name": "患者"}], "slots": [
            {"key": "GET /api/search [].id", "class": "patient", "source": "rule",
             "tier": "public", "accepts_public": true}]}"#;
        assert_eq!(refusal(both), Some(ObjectsReason::JudgementConflict));
        assert_eq!(
            ObjectsReason::JudgementConflict.code(),
            "judgement_conflict"
        );

        let alone = r#"{"classes": [{"id": "patient", "name": "患者"}], "slots": [
            {"key": "GET /api/search [].id", "class": "patient", "source": "rule",
             "reliability": "high"}]}"#;
        assert_eq!(
            refusal(alone),
            Some(ObjectsReason::ReliabilityWithoutJudgement)
        );
        assert_eq!(
            ObjectsReason::ReliabilityWithoutJudgement.code(),
            "reliability_without_judgement"
        );
    }

    #[test]
    fn an_unknown_tier_or_reliability_is_not_read() {
        let everyone = JUDGED.replace(r#""tier": "public""#, r#""tier": "everyone""#);
        assert!(serde_json::from_str::<ObjectMapDto>(&everyone).is_err());
        let sure = JUDGED.replace(r#""reliability": "high""#, r#""reliability": "certain""#);
        assert!(serde_json::from_str::<ObjectMapDto>(&sure).is_err());
    }

    #[test]
    fn confirming_a_kind_keeps_what_the_learning_judged() {
        let confirmed =
            map(JUDGED).with_entry("GET /api/search [].id", "patient", SlotSource::Admin);
        let entry = confirmed
            .slots()
            .iter()
            .find(|slot| slot.key == "GET /api/search [].id")
            .expect("the entry stays");
        assert_eq!(entry.source, SlotSource::Admin);
        assert_eq!(entry.tier, Some(Tier::Public));
        assert_eq!(entry.reliability, Some(Reliability::High));
    }

    #[test]
    fn a_paused_entry_keeps_its_judgement_and_the_judge_gets_none() {
        let paused = map(JUDGED).with_paused(&["GET /api/search [].id".to_owned()]);
        assert_eq!(paused.tier_of("GET /api/search [].id"), None);
        assert_eq!(paused.reliability_of("GET /api/search [].id"), None);
        let entry = paused
            .slots()
            .iter()
            .find(|slot| slot.key == "GET /api/search [].id")
            .expect("the entry stays");
        assert_eq!(entry.tier, Some(Tier::Public));
    }

    #[test]
    fn an_acceptance_judgement_goes_on_a_request_entry_without_a_tier() {
        let judged = map(JUDGED);
        let key = "DELETE /api/patients/{id} path[1]";
        let set = judged
            .clone()
            .with_accepts_public(key, true, Reliability::High)
            .expect("a declared request entry takes the judgement");
        assert_eq!(set.accepts_public_of(key), Some(true));
        assert_eq!(set.reliability_of(key), Some(Reliability::High));
        assert_eq!(set.tier_of(key), None);
        let written = ObjectMap::try_from(ObjectMapDto::from(set)).expect("the map stays valid");
        assert_eq!(written.accepts_public_of(key), Some(true));

        assert!(
            judged
                .clone()
                .with_accepts_public("GET /api/search [].id", true, Reliability::High)
                .is_none(),
            "an entry with a tier carries no acceptance judgement"
        );
        assert!(
            judged
                .with_accepts_public("GET /api/unknown [].id", true, Reliability::High)
                .is_none(),
            "an undeclared key takes nothing"
        );
    }

    #[test]
    fn a_tier_judgement_goes_on_a_response_entry_without_an_acceptance() {
        let judged = map(JUDGED);
        let key = "GET /api/patients [].id";
        let set = judged
            .clone()
            .with_tier(key, Tier::Public, Reliability::Medium)
            .expect("a declared response entry takes the tier");
        assert_eq!(set.tier_of(key), Some(Tier::Public));
        assert_eq!(set.reliability_of(key), Some(Reliability::Medium));
        assert_eq!(set.accepts_public_of(key), None);
        let written = ObjectMap::try_from(ObjectMapDto::from(set)).expect("the map stays valid");
        assert_eq!(written.tier_of(key), Some(Tier::Public));

        assert!(
            judged
                .clone()
                .with_tier(
                    "DELETE /api/patients/{id} path[1]",
                    Tier::Own,
                    Reliability::High
                )
                .is_none(),
            "an entry with an acceptance carries no tier"
        );
        assert!(
            judged
                .with_tier("GET /api/unknown [].id", Tier::Own, Reliability::High)
                .is_none(),
            "an undeclared key takes nothing"
        );
    }
}

#[cfg(test)]
mod function_tests {
    use serde_json::{Value, json};

    use super::*;

    /// The map a section makes. The section must be valid.
    fn map_of(section: &Value) -> ObjectMap {
        let dto: ObjectMapDto =
            serde_json::from_value(section.clone()).expect("the section parses");
        ObjectMap::try_from(dto).expect("the map is valid")
    }

    /// The refusal a section gets. The section must name one part.
    fn refusal(section: &Value) -> ObjectsIssue {
        let dto: ObjectMapDto =
            serde_json::from_value(section.clone()).expect("the section parses");
        match ObjectMap::try_from(dto) {
            Err(ConfigError::Objects(issue)) => issue,
            other => panic!("expected an objects refusal, got {other:?}"),
        }
    }

    /// A section that holds the given functions.
    fn with(functions: Vec<Value>) -> Value {
        let mut section = json!({});
        section["functions"] = Value::Array(functions);
        section
    }

    /// A function with only a key and a source: a function the site has, open to every session.
    fn open(key: &str) -> Value {
        json!({ "key": key, "source": "admin" })
    }

    /// A function that only administrators use, with the given reliability.
    fn admin(key: &str, reliability: &str) -> Value {
        json!({ "key": key, "source": "rule", "tier": "admin", "reliability": reliability })
    }

    fn key_of(map: &ObjectMap, method: &str, template: &str) -> Option<String> {
        map.function_of(method, template)
            .map(|function| function.key.clone())
    }

    #[test]
    fn functions_are_read_and_written_and_absent_when_empty() {
        let section = json!({
            "classes": [{"id": "doctor", "name": "医生"}],
            "slots": [{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"}],
            "functions": [
                {"key": "POST /api/admin/export", "source": "rule", "tier": "admin", "reliability": "high"},
                {"key": "GET /api/patients/{id}", "source": "admin"}
            ]
        });
        let loaded = map_of(&section);
        assert_eq!(loaded.functions().len(), 2);
        assert_eq!(loaded.functions()[0].key, "POST /api/admin/export");
        assert_eq!(loaded.functions()[0].source, SlotSource::Rule);
        assert_eq!(loaded.functions()[0].tier, Some(Tier::Admin));
        assert_eq!(loaded.functions()[0].reliability, Some(Reliability::High));
        assert_eq!(loaded.functions()[1].tier, None);
        assert_eq!(loaded.functions()[1].reliability, None);
        // The written form holds the entries as they were read, and reads back the same.
        let written = serde_json::to_value(&loaded).expect("the map writes");
        assert_eq!(written["functions"], section["functions"]);
        let back: ObjectMap = serde_json::from_value(written).expect("the written map reads");
        assert_eq!(back, loaded);
        // Without functions the key is not written at all.
        let plain = map_of(&json!({"slots": []}));
        assert!(plain.functions().is_empty());
        assert!(plain.is_empty());
        let with_slot = map_of(&json!({
            "classes": [{"id": "doctor", "name": "医生"}],
            "slots": [{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"}]
        }));
        let text = serde_json::to_string(&with_slot).expect("the map writes");
        assert!(!text.contains("functions"), "{text}");
    }

    #[test]
    fn a_function_key_is_a_method_and_a_canonical_template() {
        let refused_keys = [
            "GET /api/x extra".to_owned(),
            "get /api/x".to_owned(),
            "HEAD /x".to_owned(),
            "OPTIONS /x".to_owned(),
            "GET api/x".to_owned(),
            "GET /api/x?y=1".to_owned(),
            "GET /a//b".to_owned(),
            "GET /a/b/".to_owned(),
            "GET /api/users/7".to_owned(),
            "GET /api/users/{userId}".to_owned(),
            "GET /api/a;x/b".to_owned(),
            format!("GET /{}", "a".repeat(KEY_MAX)),
        ];
        for key in &refused_keys {
            assert_eq!(
                refusal(&with(vec![open(key)])),
                ObjectsIssue {
                    place: ObjectsPlace::Function(0),
                    reason: Some(ObjectsReason::KeyInvalid),
                },
                "{key}"
            );
        }
        for key in [
            "GET /",
            "GET /api/patients/{id}",
            "POST /api/admin/export",
            "GET /api/Users",
        ] {
            assert_eq!(map_of(&with(vec![open(key)])).functions().len(), 1, "{key}");
        }
    }

    #[test]
    fn a_function_tier_is_admin_only() {
        for tier in ["self", "org", "public"] {
            let section = with(vec![
                json!({"key": "GET /api/a", "source": "admin", "tier": tier}),
            ]);
            assert_eq!(
                refusal(&section),
                ObjectsIssue {
                    place: ObjectsPlace::Function(0),
                    reason: Some(ObjectsReason::FunctionTierUnsupported),
                },
                "{tier}"
            );
        }
        assert_eq!(
            ObjectsReason::FunctionTierUnsupported.code(),
            "function_tier_unsupported"
        );
        let admin_tier = map_of(&with(vec![
            json!({"key": "GET /api/a", "source": "admin", "tier": "admin"}),
        ]));
        assert_eq!(admin_tier.functions()[0].tier, Some(Tier::Admin));
    }

    #[test]
    fn a_function_reliability_needs_a_tier() {
        let section = with(vec![
            json!({"key": "GET /api/a", "source": "admin", "reliability": "high"}),
        ]);
        assert_eq!(
            refusal(&section),
            ObjectsIssue {
                place: ObjectsPlace::Function(0),
                reason: Some(ObjectsReason::ReliabilityWithoutJudgement),
            }
        );
    }

    #[test]
    fn function_keys_repeat_when_they_differ_only_by_case() {
        assert_eq!(
            refusal(&with(vec![open("GET /api/Users"), open("GET /api/users")])),
            ObjectsIssue {
                place: ObjectsPlace::Function(1),
                reason: Some(ObjectsReason::DuplicateKey),
            }
        );
        // Another method, or a template that differs in more than case, is another key.
        let distinct = with(vec![
            open("GET /api/users"),
            open("POST /api/users"),
            open("GET /api/user"),
        ]);
        assert_eq!(map_of(&distinct).functions().len(), 3);
    }

    #[test]
    fn more_functions_than_the_limit_are_refused() {
        let keyed = |count: usize| -> Vec<Value> {
            (0..count)
                .map(|index| open(&format!("GET /api/item{index}")))
                .collect()
        };
        assert_eq!(
            map_of(&with(keyed(FUNCTIONS_MAX))).functions().len(),
            FUNCTIONS_MAX
        );
        assert_eq!(
            refusal(&with(keyed(FUNCTIONS_MAX + 1))),
            ObjectsIssue {
                place: ObjectsPlace::Functions,
                reason: Some(ObjectsReason::TooMany),
            }
        );
    }

    #[test]
    fn an_exact_function_is_found() {
        let loaded = map_of(&with(vec![admin("POST /api/admin/export", "high")]));
        let found = loaded
            .function_of("POST", "/api/admin/export")
            .expect("the function is found");
        assert_eq!(found.key, "POST /api/admin/export");
        assert!(loaded.function_of("POST", "/api/admin/exports").is_none());
        assert!(loaded.function_of("GET", "/api/admin/export").is_none());
    }

    #[test]
    fn an_id_segment_covers_any_segment() {
        let loaded = map_of(&with(vec![open("GET /api/patients/{id}")]));
        for template in [
            "/api/patients/{id}",
            "/api/patients/PT-7004",
            "/api/patients/7;x=1",
        ] {
            assert!(loaded.function_of("GET", template).is_some(), "{template}");
        }
        for template in ["/api/patients", "/api/patients/7/notes"] {
            assert!(loaded.function_of("GET", template).is_none(), "{template}");
        }
    }

    #[test]
    fn an_id_segment_does_not_cover_a_route_word() {
        let loaded = map_of(&with(vec![open("GET /api/patients/{id}")]));
        for template in [
            "/api/patients/7005",
            "/api/patients/PT-7004",
            "/api/patients/9c858f3e-5b61-4d1a-8c7e-6b1c9d9f2a3b",
        ] {
            assert!(loaded.function_of("GET", template).is_some(), "{template}");
        }
        for template in [
            "/api/patients/export-all",
            "/api/patients/export-all;1",
            "/api/patients/;x",
            "/api/patients/alice",
        ] {
            assert!(loaded.function_of("GET", template).is_none(), "{template}");
        }
    }

    #[test]
    fn an_id_segment_ignores_digits_in_matrix_parameters() {
        let loaded = map_of(&with(vec![open("GET /api/patients/{id}")]));
        for template in ["/api/patients/export-all;1", "/api/patients/export-all;v=2"] {
            assert!(loaded.function_of("GET", template).is_none(), "{template}");
        }
        assert!(loaded.function_of("GET", "/api/patients/7;v=2").is_some());
    }

    #[test]
    fn a_name_segment_covers_any_segment() {
        let loaded = map_of(&with(vec![open("GET /users/{name}")]));
        for template in [
            "/users/alice",
            "/users/7005",
            "/users/PT-7004",
            "/users/{id}",
            "/users/{name}",
        ] {
            assert!(loaded.function_of("GET", template).is_some(), "{template}");
        }
        assert!(loaded.function_of("GET", "/users/;x").is_none());
    }

    #[test]
    fn an_id_entry_does_not_know_a_name_key() {
        let ids = map_of(&with(vec![open("GET /users/{id}")]));
        assert!(!ids.knows_function("GET", "/users/{name}"));
        assert!(ids.knows_function("GET", "/users/{id}"));
        let names = map_of(&with(vec![open("GET /users/{name}")]));
        assert!(names.knows_function("GET", "/users/{id}"));
    }

    #[test]
    fn the_narrower_placeholder_wins() {
        // The open `{id}` entry takes a number and the stricter `{name}` entry takes a word, whichever
        // of the two is written first.
        for entries in [
            vec![open("GET /a/{id}"), admin("GET /a/{name}", "high")],
            vec![admin("GET /a/{name}", "high"), open("GET /a/{id}")],
        ] {
            let loaded = map_of(&with(entries));
            assert_eq!(
                key_of(&loaded, "GET", "/a/123").as_deref(),
                Some("GET /a/{id}")
            );
            assert_eq!(
                key_of(&loaded, "GET", "/a/alice").as_deref(),
                Some("GET /a/{name}")
            );
        }
    }

    #[test]
    fn an_administrator_function_with_an_id_does_not_claim_a_route_word() {
        let loaded = map_of(&with(vec![admin("PUT /api/users/{id}", "high")]));
        assert!(!loaded.admin_only("PUT", "/api/users/me"));
        assert!(loaded.admin_only("PUT", "/api/users/7005"));
    }

    #[test]
    fn a_position_does_not_make_a_route_word_known() {
        let loaded = map_of(&json!({
            "classes": [{"id": "patient", "name": "患者"}],
            "slots": [
                {"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin"}
            ]
        }));
        assert!(!loaded.knows_function("GET", "/api/patients/export-all"));
        assert!(loaded.knows_function("GET", "/api/patients/7005"));
    }

    #[test]
    fn a_name_in_a_position_covers_no_route() {
        let loaded = map_of(&json!({
            "classes": [{"id": "patient", "name": "患者"}],
            "slots": [
                {"key": "GET /api/patients/{name} path[2]", "class": "patient", "source": "admin"}
            ]
        }));
        assert!(!loaded.knows_function("GET", "/api/patients/alice"));
        assert!(!loaded.knows_function("GET", "/api/patients/7005"));
    }

    #[test]
    fn a_function_key_takes_both_placeholders() {
        assert_eq!(
            map_of(&with(vec![open("GET /users/{name}")]))
                .functions()
                .len(),
            1
        );
        assert_eq!(
            map_of(&with(vec![open("GET /users/{id}")]))
                .functions()
                .len(),
            1
        );
        for key in ["GET /users/{userId}", "GET /users/{NAME}"] {
            assert_eq!(
                refusal(&with(vec![open(key)])),
                ObjectsIssue {
                    place: ObjectsPlace::Function(0),
                    reason: Some(ObjectsReason::KeyInvalid),
                },
                "{key}"
            );
        }
    }

    #[test]
    fn the_most_literal_function_wins_and_then_the_stricter() {
        let reports = map_of(&with(vec![
            open("GET /api/reports/{name}"),
            admin("GET /api/reports/monthly", "high"),
        ]));
        assert_eq!(
            key_of(&reports, "GET", "/api/reports/monthly").as_deref(),
            Some("GET /api/reports/monthly")
        );
        assert_eq!(
            key_of(&reports, "GET", "/api/reports/weekly").as_deref(),
            Some("GET /api/reports/{name}")
        );
        // Equally literal: the stricter one wins, whichever of the two is written first.
        let stricter_last = map_of(&with(vec![
            open("GET /a/{name}/c"),
            admin("GET /a/b/{name}", "high"),
        ]));
        let stricter_first = map_of(&with(vec![
            admin("GET /a/b/{name}", "high"),
            open("GET /a/{name}/c"),
        ]));
        assert_eq!(
            key_of(&stricter_last, "GET", "/a/b/c").as_deref(),
            Some("GET /a/b/{name}")
        );
        assert_eq!(
            key_of(&stricter_first, "GET", "/a/b/c").as_deref(),
            Some("GET /a/b/{name}")
        );
        // Equally literal and equally strict: the one written first wins.
        let first = map_of(&with(vec![open("GET /x/{name}"), open("GET /{name}/y")]));
        let second = map_of(&with(vec![open("GET /{name}/y"), open("GET /x/{name}")]));
        assert_eq!(
            key_of(&first, "GET", "/x/y").as_deref(),
            Some("GET /x/{name}")
        );
        assert_eq!(
            key_of(&second, "GET", "/x/y").as_deref(),
            Some("GET /{name}/y")
        );
    }

    #[test]
    fn a_function_is_found_whatever_the_case_and_matrix_parameters() {
        let loaded = map_of(&with(vec![admin("DELETE /api/admin/users/{id}", "high")]));
        assert!(loaded.admin_only("DELETE", "/API/Admin/Users/{id}"));
        assert!(loaded.admin_only("DELETE", "/api/admin;x=1/users/{id}"));
        assert!(!loaded.admin_only("DELETE", "/api/admin/users"));
    }

    #[test]
    fn head_is_looked_up_as_get_and_options_as_any_method() {
        let loaded = map_of(&with(vec![
            admin("GET /api/a", "high"),
            open("POST /api/b"),
        ]));
        assert!(loaded.admin_only("HEAD", "/api/a"));
        assert!(loaded.function_of("OPTIONS", "/api/a").is_none());
        assert!(!loaded.admin_only("OPTIONS", "/api/a"));
        assert!(loaded.knows_function("OPTIONS", "/api/b"));
        assert!(!loaded.knows_function("OPTIONS", "/api/c"));
        assert!(!loaded.knows_function("GET", "/api/b"));
    }

    #[test]
    fn only_a_high_admin_tier_is_admin_only() {
        let loaded = map_of(&with(vec![
            json!({"key": "GET /m/a", "source": "admin", "tier": "admin", "reliability": "medium"}),
            json!({"key": "GET /m/b", "source": "admin", "tier": "admin"}),
            open("GET /m/c"),
            admin("GET /m/d", "high"),
        ]));
        assert!(!loaded.admin_only("GET", "/m/a"));
        assert!(!loaded.admin_only("GET", "/m/b"));
        assert!(!loaded.admin_only("GET", "/m/c"));
        assert!(loaded.admin_only("GET", "/m/d"));
    }

    #[test]
    fn a_declared_position_makes_its_function_known() {
        let loaded = map_of(&json!({
            "classes": [{"id": "patient", "name": "患者"}],
            "slots": [
                {"key": "GET /api/patients [].id", "class": "patient", "source": "admin"},
                {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "admin", "paused": true}
            ]
        }));
        assert!(loaded.functions().is_empty());
        assert!(loaded.knows_function("GET", "/api/patients"));
        assert!(loaded.knows_function("DELETE", "/api/patients/PT-7"));
        assert!(!loaded.knows_function("POST", "/api/patients"));
        assert!(loaded.knows_function("OPTIONS", "/api/patients"));
    }

    #[test]
    fn editing_positions_keeps_the_functions() {
        let loaded = map_of(&json!({
            "classes": [{"id": "patient", "name": "患者"}],
            "slots": [
                {"key": "GET /api/patients [].id", "class": "patient", "source": "admin", "tier": "self"},
                {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "admin"}
            ],
            "functions": [
                {"key": "POST /api/admin/export", "source": "rule", "tier": "admin", "reliability": "high"},
                {"key": "GET /api/patients/{id}", "source": "admin"}
            ]
        }));
        let before = loaded.functions().to_vec();
        let edited = loaded
            .with_paused(&["GET /api/patients [].id".to_owned()])
            .with_entry("GET /api/new [].id", "patient", SlotSource::Agent)
            .with_tier("GET /api/patients [].id", Tier::Public, Reliability::Medium)
            .expect("a declared response entry takes the tier")
            .with_accepts_public(
                "DELETE /api/patients/{id} path[2]",
                false,
                Reliability::High,
            )
            .expect("a declared request entry takes the judgement");
        assert_eq!(edited.functions(), before.as_slice());
        assert!(edited.admin_only("POST", "/api/admin/export"));
        // A position an edit appends is found by the lookups too.
        assert!(edited.knows_function("GET", "/api/new"));
        assert!(!edited.knows_function("PUT", "/api/new"));
    }

    #[test]
    fn a_function_entry_takes_only_the_fields_it_names() {
        let extra = with(vec![
            json!({"key": "GET /api/a", "source": "admin", "paused": true}),
        ]);
        assert!(serde_json::from_value::<ObjectMapDto>(extra).is_err());
    }

    #[test]
    fn the_unknown_function_switch_round_trips_and_is_left_out_when_off() {
        let mut on = with(vec![open("GET /api/a")]);
        on["ask_unknown_functions"] = json!(true);
        let loaded = map_of(&on);
        assert!(loaded.asks_unknown_functions());
        let written = serde_json::to_value(&loaded).expect("the map serializes");
        assert_eq!(written["ask_unknown_functions"], json!(true));
        assert_eq!(map_of(&written), loaded);

        // Off, or left out, the key is not written at all.
        let mut off = with(vec![open("GET /api/a")]);
        off["ask_unknown_functions"] = json!(false);
        for section in [with(vec![open("GET /api/a")]), off] {
            let plain = map_of(&section);
            assert!(!plain.asks_unknown_functions());
            let text = serde_json::to_string(&plain).expect("the map serializes");
            assert!(!text.contains("ask_unknown_functions"), "{text}");
        }
    }

    #[test]
    fn a_switch_that_is_not_a_boolean_is_not_read() {
        let mut section = with(vec![open("GET /api/a")]);
        section["ask_unknown_functions"] = json!("yes");
        assert!(serde_json::from_value::<ObjectMapDto>(section).is_err());
    }

    #[test]
    fn the_switch_without_functions_is_refused() {
        let mut section = json!({});
        section["ask_unknown_functions"] = json!(true);
        let issue = refusal(&section);
        assert_eq!(issue.place, ObjectsPlace::AskUnknownFunctions);
        assert_eq!(issue.reason, Some(ObjectsReason::AskWithoutFunctions));
        assert_eq!(issue.field(), "objects.ask_unknown_functions");
        assert_eq!(
            ObjectsReason::AskWithoutFunctions.code(),
            "ask_without_functions"
        );
    }

    #[test]
    fn a_map_guards_functions_only_with_a_sure_admin_entry_or_the_switch() {
        assert!(!map_of(&json!({})).guards_functions());
        assert!(!map_of(&with(vec![open("GET /api/a")])).guards_functions());
        assert!(!map_of(&with(vec![admin("POST /api/a", "medium")])).guards_functions());
        assert!(map_of(&with(vec![admin("POST /api/a", "high")])).guards_functions());
        let mut switched = with(vec![open("GET /api/a")]);
        switched["ask_unknown_functions"] = json!(true);
        let switched = map_of(&switched);
        assert!(switched.guards_functions());
        assert!(!switched.is_empty());
    }

    #[test]
    fn with_entry_and_the_judgement_setters_keep_the_switch() {
        let mut section = with(vec![admin("GET /api/admin/search", "high")]);
        section["ask_unknown_functions"] = json!(true);
        section["classes"] = json!([{"id": "patient", "name": "患者"}]);
        section["slots"] = json!([
            {"key": "GET /api/search results[].id", "class": "patient", "source": "admin"},
            {"key": "GET /api/patients/{id} path[2]", "class": "patient", "source": "admin"},
        ]);
        let map = map_of(&section)
            .with_entry("GET /api/notes/{id} path[2]", "patient", SlotSource::Admin)
            .with_tier(
                "GET /api/search results[].id",
                Tier::Public,
                Reliability::High,
            )
            .expect("the response position takes a tier")
            .with_accepts_public("GET /api/patients/{id} path[2]", false, Reliability::High)
            .expect("the request position takes an acceptance")
            .with_paused(&["GET /api/patients/{id} path[2]".to_owned()]);
        assert!(map.asks_unknown_functions());
        assert!(map.guards_functions());
        assert_eq!(map.functions().len(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(json: &str) -> Result<ObjectMap, serde_json::Error> {
        serde_json::from_str(json)
    }

    const VALID: &str = r#"{
        "classes": [
            {"id": "doctor", "name": "医生"},
            {"id": "document", "name": "文档", "description": "病历附件"}
        ],
        "slots": [
            {"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"},
            {"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "rule"},
            {"key": "GET /api/records/{id} attachments[].doc_id", "class": "document", "source": "agent"}
        ]
    }"#;

    #[test]
    fn a_declared_id_governs_the_spellings_of_its_segment_and_the_most_specific_entry_wins() {
        let objects = map(
            r#"{"classes":[{"id":"patient","name":"患者"}],"slots":[
                {"key":"DELETE /api/patients/{id} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"},
                {"key":"DELETE /api/{id}/{id} path[2]","class":"patient","source":"admin","accepts_public":true,"reliability":"high"},
                {"key":"DELETE /api/{id}/PT-7004 path[2]","class":"patient","source":"admin","accepts_public":true,"reliability":"high"},
                {"key":"DELETE /api/patients/PT-9 path[2]","class":"patient","source":"admin","accepts_public":true,"reliability":"high","paused":true}
            ]}"#,
        )
        .unwrap();
        // The exact key of a template is the key.
        assert_eq!(
            objects.request_key("DELETE", "/api/patients/{id}", "path[2]"),
            Some("DELETE /api/patients/{id} path[2]")
        );
        // A slug the declared id covers is governed by it. The open `{id}/PT-7004` has as many
        // literal segments, and the closed entry wins that tie; `{id}/{id}` has fewer.
        assert_eq!(
            objects.request_key("DELETE", "/api/patients/PT-7004", "path[2]"),
            Some("DELETE /api/patients/{id} path[2]")
        );
        // A paused entry still names its position, though it states no access.
        assert_eq!(
            objects.request_key("DELETE", "/api/patients/PT-9", "path[2]"),
            Some("DELETE /api/patients/PT-9 path[2]")
        );
        assert_eq!(
            objects.accepts_public_of("DELETE /api/patients/PT-9 path[2]"),
            None
        );
        assert!(objects.judges_public_access());
        // Another method, another location or another number of segments is not covered.
        assert_eq!(
            objects.request_key("GET", "/api/patients/PT-7004", "path[2]"),
            None
        );
        assert_eq!(
            objects.request_key("DELETE", "/api/patients/PT-7004", "path[1]"),
            None
        );
        assert_eq!(
            objects.request_key("DELETE", "/api/patients/PT-7004/notes", "path[2]"),
            None
        );
    }

    #[test]
    fn a_site_without_public_access_places_a_value_only_by_its_exact_position() {
        let objects = map(
            r#"{"classes":[{"id":"patient","name":"患者"}],"slots":[
                {"key":"DELETE /api/patients/{id} path[2]","class":"patient","source":"admin"},
                {"key":"GET /api/search results[].id","class":"patient","source":"admin","tier":"public","reliability":"high"}]}"#,
        )
        .unwrap();
        assert!(!objects.judges_public_access());
        assert_eq!(
            objects.request_key("DELETE", "/api/patients/{id}", "path[2]"),
            Some("DELETE /api/patients/{id} path[2]")
        );
        // Without a position that takes public access, a slug is not covered by the declared id.
        assert_eq!(
            objects.request_key("DELETE", "/api/patients/PT-7004", "path[2]"),
            None
        );
    }

    #[test]
    fn confirmed_positions_look_up_their_kind() {
        let map = map(VALID).unwrap();
        assert_eq!(map.class_of("GET /doctor/{id} path[1]"), Some("doctor"));
        assert_eq!(
            map.class_of("GET /api/records/{id} attachments[].doc_id"),
            Some("document")
        );
        assert_eq!(map.class_of("GET /doctor/{id} path[2]"), None);
        assert_eq!(map.classes().len(), 2);
        assert!(!map.is_empty());
    }

    #[test]
    fn an_entry_written_again_replaces_its_own_and_a_new_key_is_appended() {
        let paused = map(&VALID.replace(
            r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"}"#,
            r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin", "paused": true}"#,
        ))
        .unwrap();
        // The paused entry is written again: its kind is back, from the source it is written with.
        let restored = paused.with_entry("GET /doctor/{id} path[1]", "doctor", SlotSource::Rule);
        assert_eq!(
            restored.class_of("GET /doctor/{id} path[1]"),
            Some("doctor")
        );
        assert!(!restored.is_paused("GET /doctor/{id} path[1]"));
        assert_eq!(restored.slots().len(), 3);
        assert_eq!(
            restored
                .slots()
                .iter()
                .find(|slot| slot.key == "GET /doctor/{id} path[1]")
                .map(|slot| slot.source),
            Some(SlotSource::Rule)
        );
        // A key the map does not declare is appended, and found by its key afterwards.
        let added = restored.with_entry("GET /other/{id} path[1]", "document", SlotSource::Agent);
        assert_eq!(added.slots().len(), 4);
        assert_eq!(
            added.declared_class_of("GET /other/{id} path[1]"),
            Some("document")
        );
        // The entries the write does not name keep their kind.
        assert_eq!(
            added.class_of("GET /api/appointments [].doc_id"),
            Some("doctor")
        );
        assert_eq!(
            added.class_of("GET /api/records/{id} attachments[].doc_id"),
            Some("document")
        );
    }

    #[test]
    fn the_map_round_trips_without_its_index() {
        let map = map(VALID).unwrap();
        let text = serde_json::to_string(&map).unwrap();
        assert!(!text.contains("index"));
        let back: ObjectMap = serde_json::from_str(&text).unwrap();
        assert_eq!(back, map);
        assert_eq!(back.class_of("GET /doctor/{id} path[1]"), Some("doctor"));
    }

    #[test]
    fn a_paused_position_keeps_its_entry_but_not_its_kind() {
        let text = VALID.replace(
            r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"}"#,
            r#"{"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin", "paused": true}"#,
        );
        let paused = map(&text).unwrap();
        assert_eq!(paused.class_of("GET /doctor/{id} path[1]"), None);
        assert_eq!(
            paused.declared_class_of("GET /doctor/{id} path[1]"),
            Some("doctor")
        );
        assert!(paused.is_paused("GET /doctor/{id} path[1]"));
        assert!(!paused.is_paused("GET /api/appointments [].doc_id"));
        assert_eq!(
            paused.class_of("GET /api/appointments [].doc_id"),
            Some("doctor")
        );
        // The flag is written only when it is set, and reads back the same.
        let written = serde_json::to_string(&paused).unwrap();
        assert!(written.contains(r#""paused":true"#), "{written}");
        assert_eq!(map(&written).unwrap(), paused);
        let plain = serde_json::to_string(&map(VALID).unwrap()).unwrap();
        assert!(!plain.contains("paused"), "{plain}");
    }

    #[test]
    fn an_empty_map_is_empty() {
        assert!(map("{}").unwrap().is_empty());
        assert!(map(r#"{"classes":[],"slots":[]}"#).unwrap().is_empty());
    }

    #[test]
    fn invalid_maps_are_refused() {
        let slot = |key: &str, class: &str| {
            format!(
                r#"{{"classes":[{{"id":"doctor","name":"医生"}}],"slots":[{{"key":"{key}","class":"{class}","source":"admin"}}]}}"#
            )
        };
        let refused = [
            // a kind that is not declared
            slot("GET /doctor/{id} path[1]", "patient"),
            // a bad kind id: upper case, too short
            r#"{"classes":[{"id":"Doctor","name":"医生"}]}"#.to_owned(),
            r#"{"classes":[{"id":"ab","name":"医生"}]}"#.to_owned(),
            // duplicate kinds and duplicate positions
            r#"{"classes":[{"id":"doctor","name":"a"},{"id":"doctor","name":"b"}]}"#.to_owned(),
            r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[{"key":"GET /d path[1]","class":"doctor","source":"admin"},{"key":"GET /d path[1]","class":"doctor","source":"rule"}]}"#.to_owned(),
            // malformed keys: lower-case method, query in the template, no location
            slot("get /doctor/{id} path[1]", "doctor"),
            slot("GET /doctor?x=1 path[1]", "doctor"),
            slot("GET /doctor/{id}", "doctor"),
            slot("GET /doctor/{id} path[1] extra", "doctor"),
            // a name that is empty
            r#"{"classes":[{"id":"doctor","name":""}]}"#.to_owned(),
            // an unknown field is refused, at the top and inside the learning settings
            r#"{"classes":[],"other":{}}"#.to_owned(),
            r#"{"learning":{"auto_learn":true,"extra":1}}"#.to_owned(),
            r#"{"learning":{"thresholds":{"uses":20,"extra":1}}}"#.to_owned(),
            // learning settings of the wrong type, or out of range
            r#"{"learning":null}"#.to_owned(),
            r#"{"learning":{"auto_learn":"yes"}}"#.to_owned(),
            r#"{"learning":{"thresholds":{"uses":0}}}"#.to_owned(),
            r#"{"learning":{"thresholds":{"sessions":0}}}"#.to_owned(),
            r#"{"learning":{"thresholds":{"uses":10001}}}"#.to_owned(),
            r#"{"learning":{"thresholds":{"sessions":-1}}}"#.to_owned(),
            r#"{"learning":{"agent":{"daily_limit":100001}}}"#.to_owned(),
        ];
        for text in refused {
            assert!(map(&text).is_err(), "should be refused: {text}");
        }
        // the agent may be switched on: the control plane decides whether it has a model to ask
        assert!(map(r#"{"learning":{"agent":{"enabled":true}}}"#).is_ok());
    }

    #[test]
    fn a_refusal_names_the_entry_and_the_reason() {
        let refusal = |text: &str| -> ObjectsIssue {
            let dto: ObjectMapDto = serde_json::from_str(text).expect("the section parses");
            match ObjectMap::try_from(dto) {
                Err(ConfigError::Objects(issue)) => issue,
                other => panic!("expected an objects refusal, got {other:?}"),
            }
        };
        let doctor = r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":["#;
        let many_slots =
            vec![r#"{"key":"GET /d path[1]","class":"doctor","source":"admin"}"#; SLOTS_MAX + 1];
        let cases = [
            (
                r#"{"classes":[{"id":"Doctor","name":"医生"}]}"#.to_owned(),
                ObjectsPlace::Class(0),
                Some(ObjectsReason::ClassIdInvalid),
            ),
            (
                r#"{"classes":[{"id":"doctor","name":"a"},{"id":"doctor","name":"b"}]}"#.to_owned(),
                ObjectsPlace::Class(1),
                Some(ObjectsReason::DuplicateKey),
            ),
            (
                r#"{"classes":[{"id":"doctor","name":""}]}"#.to_owned(),
                ObjectsPlace::Class(0),
                None,
            ),
            (
                format!(
                    r#"{{"classes":[{}]}}"#,
                    (0..=CLASSES_MAX)
                        .map(|index| format!(r#"{{"id":"kind{}","name":"k"}}"#, letters(index)))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                ObjectsPlace::Classes,
                Some(ObjectsReason::TooMany),
            ),
            (
                format!(
                    r#"{doctor}{{"key":"GET /doctor/{{id}} path[1]","class":"patient","source":"admin"}}]}}"#
                ),
                ObjectsPlace::Slot(0),
                Some(ObjectsReason::ClassUnknown),
            ),
            (
                format!(
                    r#"{doctor}{{"key":"get /doctor/{{id}} path[1]","class":"doctor","source":"admin"}}]}}"#
                ),
                ObjectsPlace::Slot(0),
                Some(ObjectsReason::KeyInvalid),
            ),
            (
                format!(
                    r#"{doctor}{{"key":"GET /d path[1]","class":"doctor","source":"admin"}},{{"key":"GET /d path[1]","class":"doctor","source":"rule"}}]}}"#
                ),
                ObjectsPlace::Slot(1),
                Some(ObjectsReason::DuplicateKey),
            ),
            (
                format!(r"{doctor}{}]}}", many_slots.join(",")),
                ObjectsPlace::Slots,
                Some(ObjectsReason::TooMany),
            ),
            (
                r#"{"learning":{"thresholds":{"uses":0}}}"#.to_owned(),
                ObjectsPlace::Learning,
                None,
            ),
        ];
        for (text, place, reason) in cases {
            assert_eq!(refusal(&text), ObjectsIssue { place, reason }, "{text}");
        }
        // The field names the entry as the API sends it.
        let slot = ObjectsIssue {
            place: ObjectsPlace::Slot(3),
            reason: Some(ObjectsReason::ClassUnknown),
        };
        assert_eq!(slot.field(), "objects.slots[3]");
        assert_eq!(slot.reason.map(ObjectsReason::code), Some("class_unknown"));
        let class = ObjectsIssue {
            place: ObjectsPlace::Class(1),
            reason: None,
        };
        assert_eq!(class.field(), "objects.classes[1]");
    }

    #[test]
    fn the_limits_hold() {
        let classes: Vec<String> = (0..=CLASSES_MAX)
            .map(|index| format!(r#"{{"id":"kind{}","name":"k"}}"#, letters(index)))
            .collect();
        let text = format!(r#"{{"classes":[{}]}}"#, classes.join(","));
        assert!(map(&text).is_err());
    }

    #[test]
    fn absent_learning_settings_are_the_defaults() {
        let loaded = map(VALID).unwrap();
        assert_eq!(loaded.learning(), &LearningSettings::default());
        assert!(loaded.learning().auto_learn);
        assert_eq!(loaded.learning().thresholds.uses, VOTES_MIN);
        assert_eq!(loaded.learning().thresholds.sessions, SESSIONS_MIN);
        assert_eq!(loaded.learning().agent.daily_limit, 200);
        assert!(!loaded.learning().agent.enabled);
        // The defaults written out in full are the same settings.
        let written = map(
            r#"{"learning":{"auto_learn":true,"auto_tighten":true,"auto_pause":true,
            "thresholds":{"uses":20,"sessions":5},"agent":{"enabled":false,"daily_limit":200}}}"#,
        )
        .unwrap();
        assert!(written.learning().is_default());
    }

    #[test]
    fn default_learning_settings_are_not_written() {
        let defaults = map(r#"{"learning":{"auto_pause":true}}"#).unwrap();
        let text = serde_json::to_string(&defaults).unwrap();
        assert!(!text.contains("learning"), "{text}");
        assert!(defaults.is_empty());
        // One setting that differs writes the whole section back, and reads back the same.
        let changed = map(r#"{"learning":{"auto_learn":false}}"#).unwrap();
        let text = serde_json::to_string(&changed).unwrap();
        assert!(text.contains(r#""learning":{"auto_learn":false"#), "{text}");
        let back: ObjectMap = serde_json::from_str(&text).unwrap();
        assert_eq!(back, changed);
        assert!(!back.is_empty());
    }

    #[test]
    fn the_learning_limits_are_inclusive() {
        let limits = serde_json::json!({"learning": {
            "thresholds": {"uses": THRESHOLD_MAX, "sessions": 1},
            "agent": {"daily_limit": AGENT_DAILY_MAX}
        }});
        let loaded: ObjectMap = serde_json::from_value(limits).unwrap();
        assert_eq!(loaded.learning().thresholds.uses, THRESHOLD_MAX);
        assert_eq!(loaded.learning().agent.daily_limit, AGENT_DAILY_MAX);
        // A daily limit of zero is allowed: the agent is off, so the limit is unused.
        assert!(map(r#"{"learning":{"agent":{"daily_limit":0}}}"#).is_ok());
    }

    #[test]
    fn a_position_states_an_identity_only_when_the_map_says_so() {
        let loaded = map(r#"{
            "classes": [{"id": "doctor", "name": "医生"}],
            "slots": [
                {"key": "GET /api/home doctor.id", "class": "doctor", "source": "admin", "identity": "user"},
                {"key": "GET /doctor/{id} path[1]", "class": "doctor", "source": "admin"}
            ]
        }"#)
        .unwrap();
        assert_eq!(
            loaded.identity_of("GET /api/home doctor.id"),
            Some(IdentityRole::User)
        );
        assert_eq!(loaded.identity_of("GET /doctor/{id} path[1]"), None);
        assert_eq!(loaded.identity_of("GET /api/me id"), None);
        // An identity names one of the three kinds; anything else is refused.
        assert!(map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"tenant"}]}"#)
        .is_err());
    }

    #[test]
    fn a_position_without_an_identity_is_written_as_before() {
        let plain = map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin"}]}"#)
        .unwrap();
        let written = serde_json::to_value(&plain).unwrap();
        assert!(written["slots"][0].get("identity").is_none());
        let stated = map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"role"}]}"#)
        .unwrap();
        let written = serde_json::to_value(&stated).unwrap();
        assert_eq!(written["slots"][0]["identity"], "role");
    }

    #[test]
    fn a_confirmed_kind_keeps_the_identity_and_a_paused_entry_states_none() {
        let loaded = map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"}]}"#)
        .unwrap();
        let confirmed = loaded.with_entry("GET /api/home doctor.id", "doctor", SlotSource::Agent);
        assert_eq!(
            confirmed.identity_of("GET /api/home doctor.id"),
            Some(IdentityRole::User)
        );
        let paused = confirmed.with_paused(&["GET /api/home doctor.id".to_owned()]);
        assert_eq!(paused.identity_of("GET /api/home doctor.id"), None);
        assert_eq!(paused.slots()[0].identity, Some(IdentityRole::User));
        let added = paused.with_entry("GET /api/me id", "doctor", SlotSource::Admin);
        assert_eq!(added.identity_of("GET /api/me id"), None);
    }

    #[test]
    fn a_site_declares_a_user_identity_only_with_an_unpaused_user_position() {
        let user = map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"}]}"#)
        .unwrap();
        assert!(user.declares_user_identity());
        let paused = map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"}]}"#)
        .unwrap()
        .with_paused(&["GET /api/home doctor.id".to_owned()]);
        assert!(!paused.declares_user_identity());
        // An organization or a role is not the user, and a map without any identity declares none.
        let org_and_role = map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /api/home org.id","class":"doctor","source":"admin","identity":"org"},
            {"key":"GET /api/home role","class":"doctor","source":"admin","identity":"role"}]}"#)
        .unwrap();
        assert!(!org_and_role.declares_user_identity());
        let none = map(r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
            {"key":"GET /doctor/{id} path[1]","class":"doctor","source":"admin"}]}"#)
        .unwrap();
        assert!(!none.declares_user_identity());
    }

    #[test]
    fn a_role_is_kept_as_a_short_label_and_anything_else_names_no_role() {
        assert_eq!(role_label(" Admin ").as_deref(), Some("admin"));
        assert_eq!(role_label("ROLE_ADMIN").as_deref(), Some("role_admin"));
        assert_eq!(
            role_label("doctor.v2:ward-3").as_deref(),
            Some("doctor.v2:ward-3")
        );
        assert_eq!(role_label(""), None);
        assert_eq!(role_label("   "), None);
        assert_eq!(role_label("管理员"), None);
        assert_eq!(role_label("a b"), None);
        assert_eq!(role_label("zhangsan@example.com"), None);
        assert_eq!(
            role_label(&"a".repeat(ROLE_MAX)).map(|role| role.len()),
            Some(ROLE_MAX)
        );
        assert_eq!(role_label(&"a".repeat(ROLE_MAX + 1)), None);
    }

    #[test]
    fn a_response_proves_by_its_tier_as_section_7_4_7_says() {
        for closed in [false, true] {
            for admin in [false, true] {
                // Own and org responses, and one the map does not classify, prove whatever the
                // reliability, the position and the session: a self response shows the session
                // its own record, so it is no less a sighting than an untiered one.
                for reliability in [Reliability::Low, Reliability::Medium, Reliability::High] {
                    assert!(tier_proves(Some((Tier::Own, reliability)), closed, admin));
                    assert!(tier_proves(Some((Tier::Org, reliability)), closed, admin));
                }
                assert!(tier_proves(None, closed, admin));
                // A public response proves unless the position is closed and the map is sure of it.
                for reliability in [Reliability::Low, Reliability::Medium] {
                    assert!(tier_proves(
                        Some((Tier::Public, reliability)),
                        closed,
                        admin
                    ));
                }
                assert_eq!(
                    tier_proves(Some((Tier::Public, Reliability::High)), closed, admin),
                    !closed
                );
                // An administrator's listing proves to an administrator session only.
                for reliability in [Reliability::Low, Reliability::Medium, Reliability::High] {
                    assert_eq!(
                        tier_proves(Some((Tier::Admin, reliability)), closed, admin),
                        admin
                    );
                }
            }
        }
    }

    /// Lower-case letters for a number, so that kind ids stay distinct.
    fn letters(mut number: usize) -> String {
        let mut text = String::new();
        loop {
            text.push(char::from(b'a' + u8::try_from(number % 26).unwrap()));
            number /= 26;
            if number == 0 {
                break;
            }
        }
        text
    }
}
