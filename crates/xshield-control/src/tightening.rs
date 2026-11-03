//! Automatic tightening of the object map (object-map design section 4): a class whose votes show
//! two groups of positions that never share a value is split, so that each further group gets a
//! class of its own.
//!
//! A split only removes fast allows. Two positions keep a fast allow after a split when a vote
//! joins them, and a vote always joins the positions of one group, so every fast allow the window
//! shows survives. The pairs that a split separates are the ones no vote joined.
//!
//! The judge matches a declared position's class against the kind a name gives an undeclared
//! position. A new class id is therefore a plural of its kind word (`doctors`): kind words never
//! end in `s`, so no name can give the new class's kind. A split never adds such a match. The
//! window check in [`adds_fast_allow`] still runs, as a second line of defence.
//!
//! Only entries the rules confirmed take part: an entry an administrator wrote, or one an agent
//! proposed, keeps its class, and so does a paused entry.

use std::collections::{BTreeMap, BTreeSet};

use xshield_core::context::objects::{ObjectClass, ObjectMapDto};
use xshield_core::context::{ObjectMap, ObjectSlot, SlotSource};

/// The shortest class id the configuration accepts. `ObjectMap::try_from` has the final say.
const ID_MIN: usize = 3;
/// The longest class id the configuration accepts.
const ID_MAX: usize = 24;
/// The longest class name the configuration accepts.
const NAME_MAX: usize = 32;

/// One class that is split. The first group keeps the class; each further group moves to a new
/// class, with the positions of that group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    /// The class that is split.
    pub class: String,
    /// The new classes, as (id, name), in the order of their groups.
    pub new_classes: Vec<(String, String)>,
    /// The positions that move, as (position key, new class id).
    pub moves: Vec<(String, String)>,
}

/// The splits the window's votes support. `votes` are (request position, the response positions its
/// value was shown at), as the store reads them, and `word_of` gives a position's kind word from
/// its name, when the name gives one.
#[must_use]
pub fn plan_splits(
    map: &ObjectMap,
    votes: &[(String, Vec<String>)],
    word_of: &dyn Fn(&str) -> Option<String>,
) -> Vec<Split> {
    // A kind word a position the map does not confirm gives. A new class must not take one: the
    // judge would then match the new class against that position's name.
    let undeclared: BTreeSet<String> = votes
        .iter()
        .flat_map(|(request, shown)| std::iter::once(request).chain(shown))
        .filter(|key| map.class_of(key).is_none())
        .filter_map(|key| word_of(key))
        .collect();
    let mut taken: BTreeSet<String> = map.classes().iter().map(|class| class.id.clone()).collect();
    let mut splits = Vec::new();
    for class in map.classes() {
        if let Some(split) = plan_class(map, &class.id, votes, word_of, &undeclared, &mut taken) {
            splits.push(split);
        }
    }
    splits
}

/// The split of one class: the groups the votes show among its positions, when there are at least
/// two. Every entry of the class must be one the rules confirmed and no one has paused.
fn plan_class(
    map: &ObjectMap,
    class: &str,
    votes: &[(String, Vec<String>)],
    word_of: &dyn Fn(&str) -> Option<String>,
    undeclared: &BTreeSet<String>,
    taken: &mut BTreeSet<String>,
) -> Option<Split> {
    let entries: Vec<&ObjectSlot> = map
        .slots()
        .iter()
        .filter(|slot| slot.class == class)
        .collect();
    if entries.is_empty()
        || entries
            .iter()
            .any(|slot| slot.source != SlotSource::Rule || slot.paused)
    {
        return None;
    }
    let members: BTreeSet<&str> = entries.iter().map(|slot| slot.key.as_str()).collect();
    let groups = groups_of(&members, votes);
    if groups.len() < 2 {
        return None;
    }
    let mut new_classes = Vec::new();
    let mut moves = Vec::new();
    for group in groups.iter().skip(1) {
        let (id, name) = fresh_class(class, group, taken, undeclared, word_of)?;
        taken.insert(id.clone());
        moves.extend(group.iter().map(|key| ((*key).to_owned(), id.clone())));
        new_classes.push((id, name));
    }
    Some(Split {
        class: class.to_owned(),
        new_classes,
        moves,
    })
}

/// The groups of the members the votes join: each connected set of members that a vote joins, and
/// that holds a position a value was shown at, in the order of its first key. A vote joins its
/// request position to the positions its value was shown at, when both are members. A member no
/// vote joins forms no group and keeps the class, as does the first group.
fn groups_of<'a>(
    members: &BTreeSet<&'a str>,
    votes: &[(String, Vec<String>)],
) -> Vec<BTreeSet<&'a str>> {
    let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut shown: BTreeSet<&str> = BTreeSet::new();
    for (request, from) in votes {
        let Some(request) = members.get(request.as_str()).copied() else {
            continue;
        };
        for key in from {
            let Some(key) = members.get(key.as_str()).copied() else {
                continue;
            };
            shown.insert(key);
            edges.entry(request).or_default().insert(key);
            edges.entry(key).or_default().insert(request);
        }
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut groups = Vec::new();
    for start in members.iter().copied() {
        if seen.contains(start) || !edges.contains_key(start) {
            continue;
        }
        let mut group = BTreeSet::new();
        let mut pending = vec![start];
        while let Some(key) = pending.pop() {
            if !group.insert(key) {
                continue;
            }
            seen.insert(key);
            if let Some(next) = edges.get(key) {
                pending.extend(next.iter().copied());
            }
        }
        if group.iter().any(|key| shown.contains(key)) {
            groups.push(group);
        }
    }
    groups
}

/// The id and name of a new class for a group. The id is the group's most common kind word in its
/// plural, the first usable candidate. The name is the word. `None` when no candidate is usable.
fn fresh_class(
    class: &str,
    group: &BTreeSet<&str>,
    taken: &BTreeSet<String>,
    undeclared: &BTreeSet<String>,
    word_of: &dyn Fn(&str) -> Option<String>,
) -> Option<(String, String)> {
    let word = most_common_word(group, word_of);
    let usable = |id: &str| {
        (ID_MIN..=ID_MAX).contains(&id.len())
            && id.bytes().all(|byte| byte.is_ascii_lowercase())
            && id != class
            && !taken.contains(id)
            && !undeclared.contains(id)
    };
    let mut candidates: Vec<String> = Vec::new();
    if let Some(word) = &word {
        candidates.push(format!("{word}s"));
    }
    candidates.push(format!("{class}s"));
    candidates.extend(('a'..='z').map(|letter| format!("{class}{letter}s")));
    let id = candidates.into_iter().find(|id| usable(id))?;
    let name: String = word
        .unwrap_or_else(|| id.clone())
        .chars()
        .take(NAME_MAX)
        .collect();
    Some((id, name))
}

/// The kind word most of a group's positions give. Ties go to the smaller word.
fn most_common_word(
    group: &BTreeSet<&str>,
    word_of: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for key in group {
        if let Some(word) = word_of(key) {
            *counts.entry(word).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
        .map(|(word, _)| word)
}

/// The map with the splits applied: each new class added, and each moved position given its new
/// class. `None` when the result is not a valid map, which keeps the configuration as it is.
#[must_use]
pub fn apply(map: &ObjectMap, splits: &[Split]) -> Option<ObjectMap> {
    let mut dto = ObjectMapDto {
        classes: map.classes().to_vec(),
        slots: map.slots().to_vec(),
        learning: *map.learning(),
    };
    for split in splits {
        for (id, name) in &split.new_classes {
            dto.classes.push(ObjectClass {
                id: id.clone(),
                name: name.clone(),
                description: String::new(),
            });
        }
        for (key, class) in &split.moves {
            for slot in dto.slots.iter_mut().filter(|slot| slot.key == *key) {
                slot.class.clone_from(class);
            }
        }
    }
    ObjectMap::try_from(dto).ok()
}

/// Whether the change from `before` to `after` gives a window vote a fast allow that `before` did
/// not give it. The judge fast-allows a value when its request position and a response position it
/// was shown at have the same declared class. Only declared classes are compared here: the window
/// check is a second line of defence, see the module notes.
#[must_use]
pub fn adds_fast_allow(
    before: &ObjectMap,
    after: &ObjectMap,
    votes: &[(String, Vec<String>)],
) -> bool {
    votes.iter().any(|(request, shown)| {
        let allowed = |map: &ObjectMap| {
            map.class_of(request)
                .is_some_and(|class| shown.iter().any(|key| map.class_of(key) == Some(class)))
        };
        allowed(after) && !allowed(before)
    })
}

#[cfg(test)]
mod tests {
    use xshield_core::context::LearningSettings;

    use super::*;

    /// The kind word of a test key: the first segment of its route, so `GET /doctor/{id} path[1]`
    /// gives `doctor`.
    fn word(key: &str) -> Option<String> {
        let route = key.split_once('/')?.1;
        route.split('/').next().map(str::to_owned)
    }

    fn slot(key: &str, class: &str) -> ObjectSlot {
        ObjectSlot {
            key: key.to_owned(),
            class: class.to_owned(),
            source: SlotSource::Rule,
            paused: false,
            identity: None,
        }
    }

    fn map_of(classes: &[&str], slots: Vec<ObjectSlot>) -> ObjectMap {
        ObjectMap::try_from(ObjectMapDto {
            classes: classes
                .iter()
                .map(|id| ObjectClass {
                    id: (*id).to_owned(),
                    name: (*id).to_owned(),
                    description: String::new(),
                })
                .collect(),
            slots,
            learning: LearningSettings::default(),
        })
        .expect("a valid test map")
    }

    const DOCTOR: &str = "GET /doctor/{id} path[1]";
    const DOCTOR_NOTES: &str = "GET /doctor/{id}/notes path[1]";
    const DOCUMENT: &str = "GET /document/{id} path[1]";
    const DOCUMENT_PARTS: &str = "GET /document/{id}/parts path[1]";

    /// A class `doc` that holds two doctor positions and two document positions. The votes join
    /// the doctors to each other and the documents to each other, and no vote crosses.
    fn two_kinds() -> (ObjectMap, Vec<(String, Vec<String>)>) {
        let map = map_of(
            &["doc"],
            vec![
                slot(DOCTOR, "doc"),
                slot(DOCTOR_NOTES, "doc"),
                slot(DOCUMENT, "doc"),
                slot(DOCUMENT_PARTS, "doc"),
            ],
        );
        let votes = vec![
            (DOCTOR.to_owned(), vec![DOCTOR_NOTES.to_owned()]),
            (DOCUMENT.to_owned(), vec![DOCUMENT_PARTS.to_owned()]),
        ];
        (map, votes)
    }

    #[test]
    fn a_class_splits_into_the_groups_its_votes_join() {
        let (map, votes) = two_kinds();
        let splits = plan_splits(&map, &votes, &word);
        assert_eq!(
            splits,
            vec![Split {
                class: "doc".to_owned(),
                new_classes: vec![("documents".to_owned(), "document".to_owned())],
                moves: vec![
                    (DOCUMENT.to_owned(), "documents".to_owned()),
                    (DOCUMENT_PARTS.to_owned(), "documents".to_owned()),
                ],
            }]
        );
        let after = apply(&map, &splits).expect("the split is a valid map");
        assert_eq!(after.class_of(DOCTOR), Some("doc"));
        assert_eq!(after.class_of(DOCUMENT), Some("documents"));
        assert!(!adds_fast_allow(&map, &after, &votes));
    }

    #[test]
    fn a_class_whose_votes_join_all_its_positions_is_not_split() {
        let (map, mut votes) = two_kinds();
        votes.push((DOCTOR.to_owned(), vec![DOCUMENT.to_owned()]));
        assert!(plan_splits(&map, &votes, &word).is_empty());
    }

    #[test]
    fn a_class_with_no_votes_is_not_split() {
        let (map, _) = two_kinds();
        assert!(plan_splits(&map, &[], &word).is_empty());
    }

    #[test]
    fn an_entry_an_administrator_wrote_keeps_its_class() {
        let (_, votes) = two_kinds();
        let mut admin = slot(DOCUMENT, "doc");
        admin.source = SlotSource::Admin;
        let map = map_of(
            &["doc"],
            vec![
                slot(DOCTOR, "doc"),
                slot(DOCTOR_NOTES, "doc"),
                admin,
                slot(DOCUMENT_PARTS, "doc"),
            ],
        );
        assert!(plan_splits(&map, &votes, &word).is_empty());
    }

    #[test]
    fn a_paused_entry_keeps_its_class() {
        let (_, votes) = two_kinds();
        let mut paused = slot(DOCUMENT, "doc");
        paused.paused = true;
        let map = map_of(
            &["doc"],
            vec![
                slot(DOCTOR, "doc"),
                slot(DOCTOR_NOTES, "doc"),
                paused,
                slot(DOCUMENT_PARTS, "doc"),
            ],
        );
        assert!(plan_splits(&map, &votes, &word).is_empty());
    }

    #[test]
    fn a_new_id_avoids_a_kind_that_an_undeclared_position_names() {
        let (map, votes) = two_kinds();
        // A window position the map does not declare names `documents` itself, so the plural id
        // is taken by a name and the split falls back to the class with an `s`.
        let mut votes = votes;
        votes.push(("GET /documents/{id} path[1]".to_owned(), Vec::new()));
        let names = |key: &str| {
            if key == "GET /documents/{id} path[1]" {
                Some("documents".to_owned())
            } else {
                word(key)
            }
        };
        let splits = plan_splits(&map, &votes, &names);
        assert_eq!(splits.len(), 1);
        assert_eq!(
            splits[0].new_classes,
            vec![("docs".to_owned(), "document".to_owned())]
        );
    }

    #[test]
    fn a_split_removes_a_crossing_fast_allow_and_adds_none() {
        let (map, votes) = two_kinds();
        let splits = plan_splits(&map, &votes, &word);
        let after = apply(&map, &splits).expect("the split is a valid map");
        // A doctor value shown at a document position was a fast allow before the split (both
        // were `doc`). No vote joined them, so the split takes that fast allow away.
        let crossing = vec![(DOCTOR.to_owned(), vec![DOCUMENT.to_owned()])];
        assert!(!adds_fast_allow(&map, &after, &crossing));
        assert_eq!(map.class_of(DOCTOR), map.class_of(DOCUMENT));
        assert_ne!(after.class_of(DOCTOR), after.class_of(DOCUMENT));
    }

    #[test]
    fn a_change_that_joins_a_request_to_its_origin_counts_as_a_new_fast_allow() {
        let map = map_of(
            &["doc", "document"],
            vec![slot(DOCTOR, "doc"), slot(DOCUMENT, "document")],
        );
        let moved = map_of(
            &["doc", "document"],
            vec![slot(DOCTOR, "document"), slot(DOCUMENT, "document")],
        );
        let votes = vec![(DOCTOR.to_owned(), vec![DOCUMENT.to_owned()])];
        assert!(adds_fast_allow(&map, &moved, &votes));
        assert!(!adds_fast_allow(&moved, &map, &votes));
    }

    #[test]
    fn an_empty_split_list_gives_back_the_same_map() {
        let (map, _) = two_kinds();
        assert_eq!(apply(&map, &[]), Some(map));
    }
}
