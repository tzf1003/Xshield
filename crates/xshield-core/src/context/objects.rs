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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::config::ConfigError;
use super::learning::{SESSIONS_MIN, VOTES_MIN};

/// Most object kinds one site declares.
pub const CLASSES_MAX: usize = 64;
/// Most confirmed positions one site holds.
pub const SLOTS_MAX: usize = 2_048;
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

/// One confirmed position and the kind of object it carries.
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
    /// paused.
    #[serde(default, skip_serializing_if = "is_false")]
    pub paused: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
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
    /// The learning settings. The default when the site sets none.
    learning: LearningSettings,
    /// Position key to its place in `slots`, built once when the map is validated.
    #[serde(skip)]
    index: BTreeMap<String, usize>,
}

impl ObjectMap {
    /// Whether the site declares nothing and keeps the default learning settings
    /// (the common case before learning).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.slots.is_empty() && self.learning.is_default()
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
        for (at, slot) in dto.slots.iter().enumerate() {
            let place = ObjectsPlace::Slot(at);
            if !valid_key(&slot.key) {
                return Err(refused(place, Some(ObjectsReason::KeyInvalid)));
            }
            if !ids.contains_key(slot.class.as_str()) {
                return Err(refused(place, Some(ObjectsReason::ClassUnknown)));
            }
            if index.insert(slot.key.clone(), at).is_some() {
                return Err(refused(place, Some(ObjectsReason::DuplicateKey)));
            }
        }
        Ok(Self {
            classes: dto.classes,
            slots: dto.slots,
            learning: dto.learning,
            index,
        })
    }
}

impl From<ObjectMap> for ObjectMapDto {
    fn from(map: ObjectMap) -> Self {
        Self {
            classes: map.classes,
            slots: map.slots,
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

/// `METHOD /template location`: an upper-case method, a path template that
/// starts with `/` and carries no query or fragment, and a location with no
/// spaces. The key is only compared, never routed, so the checks are about
/// shape: a key that cannot be produced by the judge is refused.
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
        && !location.is_empty()
        && location.len() <= 128
        && location.bytes().all(|byte| byte.is_ascii_graphic())
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
