//! The lifecycle of a learned position, and of an automatic change to the object map, as
//! explicit state machines (docs/08).
//!
//! A position is a place a request value sits at, or a response field a value was shown at.
//! The learning pass and the administrator move its row between six states. Every move is
//! one [`PositionEvent`], and the table in [`PositionEvent::from`] and [`PositionEvent::to`]
//! is the only place that says which state an event leaves and which it reaches. The store
//! binds its SQL guards from that table, and the console reads the same states, so the
//! three cannot drift apart.
//!
//! Nothing here stores anything. The control plane keeps the rows.

use serde::Serialize;

/// The learning state of a position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionState {
    /// Seen in the window, with no proposal. A dismissed position is pending too, with its
    /// dismissal kept beside the state.
    Pending,
    /// The rules or the agent propose a kind, and an administrator has yet to confirm it.
    Proposed,
    /// A declared position whose evidence still agrees with its kind.
    Confirmed,
    /// Marked uncertain by an administrator, or by a disagreement between the rules and the
    /// agent. It stays with Jev and is never proposed, judged or retired.
    Ambiguous,
    /// A declared position whose evidence now points at other kinds. It waits for an
    /// administrator.
    Suspended,
    /// Unused for longer than the retirement period. A use brings it back to pending.
    Retired,
}

impl PositionState {
    /// Every state, in the order the documents list them.
    pub const ALL: [Self; 6] = [
        Self::Pending,
        Self::Proposed,
        Self::Confirmed,
        Self::Suspended,
        Self::Ambiguous,
        Self::Retired,
    ];

    /// The state's name in the store and in the console API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Proposed => "proposed",
            Self::Confirmed => "confirmed",
            Self::Ambiguous => "ambiguous",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    /// The state a stored or submitted name means, if it is one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.as_str() == value)
    }

    /// The state `event` moves this state to, or `None` when the event does not apply to it.
    /// The store's guards say the same, so a refused event changes no row.
    #[must_use]
    pub fn on(self, event: PositionEvent) -> Option<Self> {
        event.from().contains(&self).then(|| event.to())
    }
}

/// Something that moves a position between states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PositionEvent {
    /// A vote used the position again after it was retired.
    Seen,
    /// The rules or the agent give the position a kind. A dismissed position takes the
    /// proposal only once its evidence has changed significantly; the store checks that.
    Propose,
    /// The pass finds the position declared and its evidence in agreement.
    Confirm,
    /// The pass finds the position declared and its evidence pointing elsewhere, or paused.
    Suspend,
    /// The pass no longer has a kind for a proposal.
    Withdraw,
    /// The administrator dismisses the proposal, or the position while it has none.
    Dismiss,
    /// The administrator marks the position uncertain.
    MarkAmbiguous,
    /// The rules and the agent disagree about the position's kind.
    Dispute,
    /// The administrator confirms a suspended position again.
    Reconfirm,
    /// The position went unused for the retirement period.
    Retire,
}

impl PositionEvent {
    /// Every event, in the order the documents list them.
    pub const ALL: [Self; 10] = [
        Self::Seen,
        Self::Propose,
        Self::Confirm,
        Self::Suspend,
        Self::Withdraw,
        Self::Dismiss,
        Self::MarkAmbiguous,
        Self::Dispute,
        Self::Reconfirm,
        Self::Retire,
    ];

    /// The states the event applies to. A position in any other state is left as it is.
    #[must_use]
    pub const fn from(self) -> &'static [PositionState] {
        use PositionState::{Confirmed, Pending, Proposed, Retired, Suspended};
        match self {
            Self::Seen => &[Retired],
            // An ambiguous position is never judged.
            Self::Propose | Self::Suspend => &[Pending, Proposed, Confirmed, Suspended, Retired],
            // A suspension waits for an administrator: the pass never lifts it.
            Self::Confirm => &[Pending, Proposed, Confirmed, Retired],
            Self::Withdraw => &[Proposed],
            Self::Dismiss | Self::MarkAmbiguous => &[Pending, Proposed, Suspended],
            Self::Dispute => &[Pending, Proposed],
            Self::Reconfirm => &[Suspended],
            // An ambiguous position is kept until an administrator decides it.
            Self::Retire => &[Pending, Proposed, Confirmed, Suspended],
        }
    }

    /// The state the event reaches.
    #[must_use]
    pub const fn to(self) -> PositionState {
        match self {
            Self::Seen | Self::Withdraw | Self::Dismiss => PositionState::Pending,
            Self::Propose => PositionState::Proposed,
            Self::Confirm | Self::Reconfirm => PositionState::Confirmed,
            Self::Suspend => PositionState::Suspended,
            Self::MarkAmbiguous | Self::Dispute => PositionState::Ambiguous,
            Self::Retire => PositionState::Retired,
        }
    }

    /// The names of the states the event applies to, as the store binds them.
    #[must_use]
    pub fn from_names(self) -> Vec<&'static str> {
        self.from().iter().map(|state| state.as_str()).collect()
    }

    /// The event's name in the documents.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Seen => "seen",
            Self::Propose => "propose",
            Self::Confirm => "confirm",
            Self::Suspend => "suspend",
            Self::Withdraw => "withdraw",
            Self::Dismiss => "dismiss",
            Self::MarkAmbiguous => "mark_ambiguous",
            Self::Dispute => "dispute",
            Self::Reconfirm => "reconfirm",
            Self::Retire => "retire",
        }
    }
}

/// The position lifecycle as a Mermaid state diagram: one arrow per pair of states an event
/// joins, labelled with every event that joins them. An event that leaves a state as it is
/// draws no arrow. docs/08 holds this text, and a test keeps the two the same.
#[must_use]
pub fn position_diagram() -> String {
    let mut lines = vec![
        "stateDiagram-v2".to_owned(),
        "    [*] --> pending: first seen".to_owned(),
    ];
    for from in PositionState::ALL {
        for to in PositionState::ALL {
            let events: Vec<&str> = PositionEvent::ALL
                .into_iter()
                .filter(|event| from != to && from.on(*event) == Some(to))
                .map(PositionEvent::as_str)
                .collect();
            if !events.is_empty() {
                lines.push(format!(
                    "    {} --> {}: {}",
                    from.as_str(),
                    to.as_str(),
                    events.join(", ")
                ));
            }
        }
    }
    lines.push("    retired --> [*]: forgotten".to_owned());
    lines.join("\n")
}

/// How an administrator handled an automatic change to the object map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Handling {
    /// Known to the administrator, with the configuration unchanged.
    Acknowledged,
    /// Undone by a save, which named the change.
    Undone,
}

impl Handling {
    /// The handling's name in the store and in the console API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledged => "acknowledged",
            Self::Undone => "undone",
        }
    }

    /// The handling a stored name means, if it is one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::Acknowledged, Self::Undone]
            .into_iter()
            .find(|handling| handling.as_str() == value)
    }
}

/// Where an automatic change stands: `status` in the console API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventState {
    /// No one handled the change, and the configuration still holds the entry it made.
    Open,
    /// Known to the administrator, with the configuration unchanged.
    Acknowledged,
    /// Undone by a save, which named the change.
    Undone,
    /// A later version changed the same entry, so the change no longer describes it.
    Superseded,
}

/// Why an automatic change does not take a handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventRefusal {
    /// A save undid the change already.
    Undone,
    /// A later version changed the entry.
    Superseded,
}

impl EventState {
    /// Every state, in the order the documents list them.
    pub const ALL: [Self; 4] = [
        Self::Open,
        Self::Acknowledged,
        Self::Undone,
        Self::Superseded,
    ];

    /// The state's name in the console API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Undone => "undone",
            Self::Superseded => "superseded",
        }
    }

    /// The state of a change from its stored handling, and from whether the configuration
    /// still holds the entry the change made.
    #[must_use]
    pub const fn of(handling: Option<Handling>, still_current: bool) -> Self {
        match handling {
            Some(Handling::Acknowledged) => Self::Acknowledged,
            Some(Handling::Undone) => Self::Undone,
            None if still_current => Self::Open,
            None => Self::Superseded,
        }
    }

    /// The state after an administrator handles the change. `Ok(None)` when the change is
    /// handled that way already and nothing is written.
    ///
    /// # Errors
    /// [`EventRefusal`] for a change that is undone, or that a later version changed.
    pub const fn handle(self, handling: Handling) -> Result<Option<Self>, EventRefusal> {
        match (self, handling) {
            (Self::Open, Handling::Acknowledged) => Ok(Some(Self::Acknowledged)),
            (Self::Acknowledged, Handling::Acknowledged) => Ok(None),
            (Self::Open | Self::Acknowledged, Handling::Undone) => Ok(Some(Self::Undone)),
            (Self::Undone, _) => Err(EventRefusal::Undone),
            (Self::Superseded, _) => Err(EventRefusal::Superseded),
        }
    }
}

/// The handling of an automatic change as a Mermaid state diagram. docs/08 holds this text,
/// and a test keeps the two the same.
#[must_use]
pub fn event_diagram() -> String {
    let mut lines = vec![
        "stateDiagram-v2".to_owned(),
        "    [*] --> open: automatic change".to_owned(),
        "    open --> superseded: later version changes the entry".to_owned(),
    ];
    for from in EventState::ALL {
        for (handling, label) in [(Handling::Acknowledged, "ack"), (Handling::Undone, "undo")] {
            if let Ok(Some(to)) = from.handle(handling) {
                lines.push(format!(
                    "    {} --> {}: {label}",
                    from.as_str(),
                    to.as_str()
                ));
            }
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = include_str!("../../../../docs/08-state-machines.md");

    /// The Mermaid block that follows `heading` in docs/08.
    fn documented(heading: &str) -> String {
        let section = DOC
            .split_once(heading)
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        section
            .split_once("```mermaid\n")
            .and_then(|(_, rest)| rest.split_once("\n```"))
            .map(|(diagram, _)| diagram.to_owned())
            .unwrap_or_default()
    }

    #[test]
    fn the_documented_diagrams_are_the_ones_the_tables_draw() {
        assert_eq!(documented("## 1. "), position_diagram());
        assert_eq!(documented("## 2. "), event_diagram());
    }

    #[test]
    fn names_round_trip() {
        for state in PositionState::ALL {
            assert_eq!(PositionState::parse(state.as_str()), Some(state));
            assert_eq!(
                serde_json::to_value(state).ok(),
                Some(serde_json::Value::from(state.as_str()))
            );
        }
        assert_eq!(PositionState::parse("dismissed"), None);
        for handling in [Handling::Acknowledged, Handling::Undone] {
            assert_eq!(Handling::parse(handling.as_str()), Some(handling));
        }
        assert_eq!(Handling::parse("open"), None);
    }

    #[test]
    fn an_event_moves_only_the_states_it_applies_to() {
        for event in PositionEvent::ALL {
            for state in PositionState::ALL {
                let moved = state.on(event);
                if event.from().contains(&state) {
                    assert_eq!(moved, Some(event.to()));
                } else {
                    assert_eq!(moved, None);
                }
            }
        }
    }

    #[test]
    fn an_ambiguous_position_waits_for_an_administrator() {
        for event in PositionEvent::ALL {
            assert_eq!(PositionState::Ambiguous.on(event), None, "{event:?}");
        }
    }

    #[test]
    fn the_pass_never_lifts_a_suspension() {
        assert_eq!(PositionState::Suspended.on(PositionEvent::Confirm), None);
        assert_eq!(
            PositionState::Suspended.on(PositionEvent::Reconfirm),
            Some(PositionState::Confirmed)
        );
    }

    #[test]
    fn a_confirmed_position_is_neither_dismissed_nor_marked_ambiguous() {
        for event in [
            PositionEvent::Dismiss,
            PositionEvent::MarkAmbiguous,
            PositionEvent::Dispute,
        ] {
            assert_eq!(PositionState::Confirmed.on(event), None, "{event:?}");
        }
    }

    #[test]
    fn only_a_use_brings_a_retired_position_back_to_pending() {
        assert_eq!(
            PositionState::Retired.on(PositionEvent::Seen),
            Some(PositionState::Pending)
        );
        for state in PositionState::ALL {
            if state != PositionState::Retired {
                assert_eq!(state.on(PositionEvent::Seen), None);
            }
        }
    }

    #[test]
    fn an_event_is_handled_at_most_twice() {
        use EventState::{Acknowledged, Open, Superseded, Undone};
        assert_eq!(Open.handle(Handling::Acknowledged), Ok(Some(Acknowledged)));
        assert_eq!(Acknowledged.handle(Handling::Acknowledged), Ok(None));
        assert_eq!(Open.handle(Handling::Undone), Ok(Some(Undone)));
        assert_eq!(Acknowledged.handle(Handling::Undone), Ok(Some(Undone)));
        for handling in [Handling::Acknowledged, Handling::Undone] {
            assert_eq!(Undone.handle(handling), Err(EventRefusal::Undone));
            assert_eq!(Superseded.handle(handling), Err(EventRefusal::Superseded));
        }
    }

    #[test]
    fn a_stored_handling_decides_the_state_before_the_configuration_does() {
        for current in [true, false] {
            assert_eq!(
                EventState::of(Some(Handling::Acknowledged), current),
                EventState::Acknowledged
            );
            assert_eq!(
                EventState::of(Some(Handling::Undone), current),
                EventState::Undone
            );
        }
        assert_eq!(EventState::of(None, true), EventState::Open);
        assert_eq!(EventState::of(None, false), EventState::Superseded);
    }
}
