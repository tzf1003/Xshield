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
//! learning state, not by the site configuration, so a configuration version
//! changes only when the map itself does.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::config::ConfigError;

/// Most object kinds one site declares.
pub const CLASSES_MAX: usize = 64;
/// Most confirmed positions one site holds.
pub const SLOTS_MAX: usize = 2_048;
/// Longest position key, in bytes.
pub const KEY_MAX: usize = 256;
/// Shortest and longest kind id, in bytes (lower-case ASCII letters).
const CLASS_ID_MIN: usize = 3;
const CLASS_ID_MAX: usize = 24;
/// Longest display name and description, in characters.
const NAME_MAX: usize = 32;
const DESCRIPTION_MAX: usize = 200;

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
}

/// A validated object map. Lookups go through [`ObjectMap::class_of`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ObjectMapDto", into = "ObjectMapDto")]
pub struct ObjectMap {
    classes: Vec<ObjectClass>,
    slots: Vec<ObjectSlot>,
    /// Position key to kind id, built once when the map is validated.
    #[serde(skip)]
    index: BTreeMap<String, String>,
}

impl ObjectMap {
    /// Whether the site declares nothing (the common case before learning).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.slots.is_empty()
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

    /// The kind of object a position carries, when the map confirms one.
    #[must_use]
    pub fn class_of(&self, key: &str) -> Option<&str> {
        self.index.get(key).map(String::as_str)
    }
}

impl TryFrom<ObjectMapDto> for ObjectMap {
    type Error = ConfigError;

    fn try_from(dto: ObjectMapDto) -> Result<Self, ConfigError> {
        if dto.classes.len() > CLASSES_MAX || dto.slots.len() > SLOTS_MAX {
            return Err(ConfigError::Objects);
        }
        let mut ids = BTreeMap::new();
        for class in &dto.classes {
            if !valid_class_id(&class.id)
                || class.name.is_empty()
                || class.name.chars().count() > NAME_MAX
                || class.description.chars().count() > DESCRIPTION_MAX
                || ids.insert(class.id.as_str(), ()).is_some()
            {
                return Err(ConfigError::Objects);
            }
        }
        let mut index = BTreeMap::new();
        for slot in &dto.slots {
            if !valid_key(&slot.key)
                || !ids.contains_key(slot.class.as_str())
                || index.insert(slot.key.clone(), slot.class.clone()).is_some()
            {
                return Err(ConfigError::Objects);
            }
        }
        Ok(Self {
            classes: dto.classes,
            slots: dto.slots,
            index,
        })
    }
}

impl From<ObjectMap> for ObjectMapDto {
    fn from(map: ObjectMap) -> Self {
        Self {
            classes: map.classes,
            slots: map.slots,
        }
    }
}

/// `lower-case` letters only, 3 to 24 bytes, as the kind rules of the
/// field-kind declarations use.
fn valid_class_id(id: &str) -> bool {
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
            // an unknown field is refused
            r#"{"classes":[],"learning":{}}"#.to_owned(),
        ];
        for text in refused {
            assert!(map(&text).is_err(), "should be refused: {text}");
        }
    }

    #[test]
    fn the_limits_hold() {
        let classes: Vec<String> = (0..=CLASSES_MAX)
            .map(|index| format!(r#"{{"id":"kind{}","name":"k"}}"#, letters(index)))
            .collect();
        let text = format!(r#"{{"classes":[{}]}}"#, classes.join(","));
        assert!(map(&text).is_err());
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
