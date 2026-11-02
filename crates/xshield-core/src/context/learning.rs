//! Evidence for learning the object map (the object-map design note, sections
//! 3 and 5).
//!
//! The gateway records where each request value sits (its position) and, for a
//! value an origin showed, the response position it came from. This module
//! turns decision records into votes, and the votes into a proposal or a
//! warning. Only the origin's own answers count: a request that went through
//! and whose origin answered 2xx is a use, and a use counts once per position,
//! session and UTC day. A refusal by Jev is a denial, and a denial stops any
//! proposal for the position.
//!
//! Nothing here stores anything or changes a site. The control plane keeps the
//! votes, and an administrator confirms a proposal before it reaches the map.

use std::collections::{BTreeMap, BTreeSet};

use super::log::{DecisionPath, Outcome};
use super::objects::ObjectMap;
use super::trace::Trace;

/// Days of evidence a position is judged on.
pub const WINDOW_DAYS: u64 = 7;
/// Days a position may go unseen before it is retired.
pub const RETIRE_DAYS: u64 = 30;
/// Votes a position needs before the rules may propose a kind for it.
pub const VOTES_MIN: u32 = 20;
/// Sessions a position needs before the rules may propose a kind for it.
pub const SESSIONS_MIN: u32 = 5;
/// Share of votes, in thousandths, that the response positions of one kind must hold.
pub const SHARE_PER_MILLE: u32 = 900;

const DAY_MILLIS: u64 = 86_400_000;

/// The thresholds a proposal or a warning is judged against. The defaults are
/// the ones the design gives; a site may raise or lower them later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// Votes needed.
    pub votes: u32,
    /// Sessions needed.
    pub sessions: u32,
    /// Share of votes, in thousandths, one kind's response positions must hold.
    pub share_per_mille: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            votes: VOTES_MIN,
            sessions: SESSIONS_MIN,
            share_per_mille: SHARE_PER_MILLE,
        }
    }
}

/// One use of a request position: the value went through, and the origin
/// answered 2xx.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    /// The request position, `METHOD route location`.
    pub slot: String,
    /// The session that used the value.
    pub session: String,
    /// The UTC day of the use, counted from the epoch.
    pub day: u64,
    /// The response positions the value was shown at, as the record names them.
    pub from: Vec<String>,
}

/// One refusal by Jev of a request that used a position.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Denial {
    /// The request position, `METHOD route location`.
    pub slot: String,
    /// The session that was refused.
    pub session: String,
    /// The UTC day of the refusal, counted from the epoch.
    pub day: u64,
}

/// What one decision record says about the positions of its values.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Observed {
    /// Uses that count as votes.
    pub votes: Vec<Vote>,
    /// Refusals by Jev.
    pub denials: Vec<Denial>,
}

/// What the learning reads from one decision record: when it was judged, the
/// session, the status and the step that settled it, and its trace. The
/// control plane builds it from a decision log row.
#[derive(Debug, Clone)]
pub struct DecisionFacts {
    /// When the request reached the gateway, Unix milliseconds.
    pub at_millis: u64,
    /// The session label; empty when the decision had no session.
    pub session: String,
    /// The status returned to the client.
    pub status: Option<u16>,
    /// The step that settled the decision.
    pub decision_path: DecisionPath,
    /// What the gateway did.
    pub outcome: Outcome,
    /// The trace, with the position of each value and of the source it came from.
    pub trace: Trace,
}

/// Reads one decision record. A request counts as a use when it went through
/// (`allowed`, not an observe-mode `would_block`) and the origin answered 2xx.
/// A value without a position, and a value the gateway did not judge, counts
/// for nothing. A use without a session casts no vote, since anonymous uses
/// cannot be told apart.
#[must_use]
pub fn observe(record: &DecisionFacts) -> Observed {
    let day = record.at_millis / DAY_MILLIS;
    let used = record.outcome == Outcome::Allowed
        && record
            .status
            .is_some_and(|status| (200..300).contains(&status))
        && matches!(
            record.decision_path,
            DecisionPath::FastAllow | DecisionPath::CachedAllow | DecisionPath::JevAllow
        );
    let refused = record.decision_path == DecisionPath::JevDeny;
    let mut observed = Observed::default();
    for value in &record.trace.values {
        if value.inert {
            continue;
        }
        let Some(slot) = &value.slot else {
            continue;
        };
        if used && !record.session.is_empty() {
            let from = value
                .sources
                .iter()
                .filter_map(|source| source.slot.clone())
                .collect();
            observed.votes.push(Vote {
                slot: slot.clone(),
                session: record.session.clone(),
                day,
                from,
            });
        }
        if refused {
            observed.denials.push(Denial {
                slot: slot.clone(),
                session: record.session.clone(),
                day,
            });
        }
    }
    observed
}

/// The evidence of one request position: its votes and denials, one of each
/// per session and day at most.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// The response positions each (session, day) vote was shown at.
    votes: BTreeMap<(String, u64), Vec<String>>,
    /// The (session, day) pairs that were refused.
    denials: BTreeSet<(String, u64)>,
}

impl Evidence {
    /// Adds a vote. A second vote from the same session on the same day changes nothing.
    pub fn add_vote(&mut self, vote: Vote) {
        self.votes
            .entry((vote.session, vote.day))
            .or_insert(vote.from);
    }

    /// Adds a denial. A session refused twice on one day counts once.
    pub fn add_denial(&mut self, denial: Denial) {
        self.denials.insert((denial.session, denial.day));
    }

    /// Drops the evidence older than the window ending on `today`.
    pub fn prune(&mut self, today: u64) {
        let oldest = today.saturating_sub(WINDOW_DAYS - 1);
        self.votes.retain(|(_, day), _| *day >= oldest);
        self.denials.retain(|(_, day)| *day >= oldest);
    }

    /// The number of votes.
    #[must_use]
    pub fn votes(&self) -> u32 {
        saturating_count(self.votes.len())
    }

    /// The number of distinct sessions that voted.
    #[must_use]
    pub fn sessions(&self) -> u32 {
        let sessions: BTreeSet<&str> = self
            .votes
            .keys()
            .map(|(session, _)| session.as_str())
            .collect();
        saturating_count(sessions.len())
    }

    /// The number of refusals.
    #[must_use]
    pub fn denials(&self) -> u32 {
        saturating_count(self.denials.len())
    }

    /// How many votes each kind of object holds, by the kinds the map confirms for
    /// their response positions. A vote counts toward a kind only when every one of
    /// its positions the map names has that kind. A vote whose positions disagree,
    /// or that no position of the map names, counts toward no kind (it still counts
    /// in `votes`).
    #[must_use]
    pub fn kinds<'a>(&'a self, map: &'a ObjectMap) -> BTreeMap<&'a str, u32> {
        let mut kinds = BTreeMap::new();
        for positions in self.votes.values() {
            let mut named = positions
                .iter()
                .filter_map(|position| map.class_of(position));
            let Some(first) = named.next() else {
                continue;
            };
            if named.all(|class| class == first) {
                *kinds.entry(first).or_insert(0) += 1;
            }
        }
        kinds
    }

    /// The most recent day with a vote, when there is one.
    #[must_use]
    pub fn last_day(&self) -> Option<u64> {
        self.votes.keys().map(|(_, day)| *day).max()
    }
}

/// A kind the rules propose for a request position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The kind of object, a class id of the map.
    pub class: String,
    /// The votes the proposal rests on.
    pub votes: u32,
    /// The sessions the proposal rests on.
    pub sessions: u32,
    /// The share of votes whose response position is of `class`, in thousandths.
    pub share_per_mille: u32,
}

/// The kind the rules propose for a request position, when they can tell it.
///
/// A proposal needs the thresholds met and no refusal in the window. Then one
/// kind, counted from the response positions the map confirms, must hold the
/// share of votes. Votes whose response position the map does not confirm
/// count toward the total but toward no kind. When no kind qualifies, the rules
/// cannot tell and the position goes to the agent. The evidence must be pruned
/// to the window first (`Evidence::prune`): this function does not drop old votes.
#[must_use]
pub fn propose(evidence: &Evidence, map: &ObjectMap, thresholds: Thresholds) -> Option<Proposal> {
    let votes = evidence.votes();
    if votes < thresholds.votes
        || evidence.sessions() < thresholds.sessions
        || evidence.denials() > 0
    {
        return None;
    }
    let (class, count) = evidence
        .kinds(map)
        .into_iter()
        .max_by_key(|(_, count)| *count)?;
    if !meets_share(count, votes, thresholds.share_per_mille) {
        return None;
    }
    Some(Proposal {
        class: class.to_owned(),
        votes,
        sessions: evidence.sessions(),
        share_per_mille: share_of(count, votes),
    })
}

/// Whether the evidence of a confirmed position points at another kind: one
/// other kind holds the share of the votes on its own. Votes split across several
/// other kinds do not add up to a conflict. A confirmed position that the rules no
/// longer support should be suspended rather than trusted. The evidence must be
/// pruned to the window first (`Evidence::prune`).
#[must_use]
pub fn contradicts(
    confirmed: &str,
    evidence: &Evidence,
    map: &ObjectMap,
    thresholds: Thresholds,
) -> bool {
    let votes = evidence.votes();
    if votes < thresholds.votes || evidence.sessions() < thresholds.sessions {
        return false;
    }
    evidence.kinds(map).into_iter().any(|(kind, count)| {
        kind != confirmed && meets_share(count, votes, thresholds.share_per_mille)
    })
}

/// Whether a position unseen since `last_day` is retired on `today`.
#[must_use]
pub fn is_retired(last_day: u64, today: u64) -> bool {
    today.saturating_sub(last_day) >= RETIRE_DAYS
}

/// The UTC day a time in milliseconds falls on, counted from the epoch.
#[must_use]
pub fn day_of(at_millis: u64) -> u64 {
    at_millis / DAY_MILLIS
}

fn meets_share(count: u32, votes: u32, share_per_mille: u32) -> bool {
    votes > 0 && u64::from(count) * 1_000 >= u64::from(votes) * u64::from(share_per_mille)
}

fn share_of(count: u32, votes: u32) -> u32 {
    let share = u64::from(count) * 1_000 / u64::from(votes.max(1));
    u32::try_from(share).unwrap_or(u32::MAX)
}

fn saturating_count(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ObjectMap;

    const DAY: u64 = 86_400_000;

    fn map() -> ObjectMap {
        serde_json::from_str::<ObjectMap>(
            r#"{
                "classes": [{"id": "doctor", "name": "医生"}, {"id": "document", "name": "文档"}],
                "slots": [
                    {"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "rule"},
                    {"key": "GET /api/docs [].id", "class": "document", "source": "admin"}
                ]
            }"#,
        )
        .unwrap()
    }

    fn vote(session: &str, day: u64, from: Option<&str>) -> Vote {
        Vote {
            slot: "GET /doctor/{id} path[1]".to_owned(),
            session: session.to_owned(),
            day,
            from: from.map(str::to_owned).into_iter().collect(),
        }
    }

    /// Evidence with `count` votes from `sessions` sessions, all from `from`.
    fn evidence(count: u32, sessions: u32, from: Option<&str>) -> Evidence {
        let mut evidence = Evidence::default();
        for index in 0..count {
            evidence.add_vote(vote(
                &format!("s{}", index % sessions),
                u64::from(index),
                from,
            ));
        }
        evidence
    }

    #[test]
    fn a_vote_counts_once_per_session_and_day() {
        let mut evidence = Evidence::default();
        evidence.add_vote(vote("a", 1, Some("GET /api/appointments [].doc_id")));
        evidence.add_vote(vote("a", 1, None));
        evidence.add_vote(vote("a", 2, None));
        evidence.add_vote(vote("b", 1, None));
        assert_eq!(evidence.votes(), 3);
        assert_eq!(evidence.sessions(), 2);
        // The first vote of the day keeps its response position.
        assert_eq!(evidence.kinds(&map()).get("doctor"), Some(&1));
        assert_eq!(evidence.last_day(), Some(2));
    }

    #[test]
    fn a_refusal_counts_once_per_session_and_day() {
        let mut evidence = Evidence::default();
        for _ in 0..3 {
            evidence.add_denial(Denial {
                slot: "GET /doctor/{id} path[1]".to_owned(),
                session: "a".to_owned(),
                day: 1,
            });
        }
        assert_eq!(evidence.denials(), 1);
    }

    #[test]
    fn evidence_older_than_the_window_is_dropped() {
        let mut evidence = Evidence::default();
        evidence.add_vote(vote("a", 10, None));
        evidence.add_vote(vote("b", 11, None));
        evidence.add_vote(vote("c", 16, None));
        // The window ending on day 16 holds days 10 to 16 when it is seven days.
        evidence.prune(16);
        assert_eq!(evidence.votes(), 3);
        evidence.prune(17);
        assert_eq!(evidence.votes(), 2);
        evidence.prune(20);
        assert_eq!(evidence.votes(), 1);
    }

    #[test]
    fn a_proposal_needs_the_thresholds_and_no_refusal() {
        let map = map();
        let from = Some("GET /api/appointments [].doc_id");
        let thresholds = Thresholds::default();
        // Exactly at the thresholds, all from a doctor position: proposed.
        let proposal = propose(&evidence(20, 5, from), &map, thresholds).unwrap();
        assert_eq!(proposal.class, "doctor");
        assert_eq!(proposal.votes, 20);
        assert_eq!(proposal.sessions, 5);
        assert_eq!(proposal.share_per_mille, 1_000);
        // One vote short, or one session short: not yet.
        assert!(propose(&evidence(19, 5, from), &map, thresholds).is_none());
        assert!(propose(&evidence(20, 4, from), &map, thresholds).is_none());
        // A single refusal in the window stops the proposal.
        let mut refused = evidence(20, 5, from);
        refused.add_denial(Denial {
            slot: "GET /doctor/{id} path[1]".to_owned(),
            session: "s1".to_owned(),
            day: 3,
        });
        assert!(propose(&refused, &map, thresholds).is_none());
    }

    #[test]
    fn a_proposal_needs_ninety_per_cent_from_one_confirmed_kind() {
        let map = map();
        let doctor = Some("GET /api/appointments [].doc_id");
        let mut mixed = evidence(18, 5, doctor);
        // 18 of 20 is exactly 90 per cent.
        for index in 0..2 {
            mixed.add_vote(vote(
                &format!("x{index}"),
                50 + index,
                Some("GET /api/other [].id"),
            ));
        }
        assert_eq!(
            propose(&mixed, &map, Thresholds::default())
                .unwrap()
                .share_per_mille,
            900
        );
        // 17 of 20 is 85 per cent: the rules cannot tell.
        let mut unclear = evidence(17, 5, doctor);
        for index in 0..3 {
            unclear.add_vote(vote(
                &format!("y{index}"),
                60 + index,
                Some("GET /api/other [].id"),
            ));
        }
        assert!(propose(&unclear, &map, Thresholds::default()).is_none());
    }

    #[test]
    fn votes_without_a_mapped_source_count_toward_no_kind() {
        let map = map();
        // Every vote came from a position the map does not confirm, or from none.
        let unmapped = evidence(20, 5, Some("GET /api/other [].id"));
        assert!(propose(&unmapped, &map, Thresholds::default()).is_none());
        let unseen = evidence(20, 5, None);
        assert!(propose(&unseen, &map, Thresholds::default()).is_none());
    }

    #[test]
    fn a_confirmed_kind_that_the_flow_contradicts_is_reported() {
        let map = map();
        let documents = Some("GET /api/docs [].id");
        let flow = evidence(20, 5, documents);
        // Confirmed as a doctor, but the value now comes from documents: contradicted.
        assert!(contradicts("doctor", &flow, &map, Thresholds::default()));
        // Confirmed as a document: the flow agrees.
        assert!(!contradicts("document", &flow, &map, Thresholds::default()));
        // Too little evidence says nothing.
        assert!(!contradicts(
            "doctor",
            &evidence(10, 5, documents),
            &map,
            Thresholds::default()
        ));
    }

    #[test]
    fn a_split_flow_is_not_a_contradiction() {
        let map = serde_json::from_str::<ObjectMap>(
            r#"{
                "classes": [{"id": "doctor", "name": "医生"}, {"id": "document", "name": "文档"}, {"id": "patient", "name": "患者"}],
                "slots": [
                    {"key": "GET /api/appointments [].doc_id", "class": "doctor", "source": "rule"},
                    {"key": "GET /api/docs [].id", "class": "document", "source": "admin"},
                    {"key": "GET /api/patients [].id", "class": "patient", "source": "admin"}
                ]
            }"#,
        )
        .unwrap();
        // Confirmed as a doctor. Half the votes come from documents and half from
        // patients: neither other kind holds the share on its own.
        let mut split = Evidence::default();
        for index in 0..20_u32 {
            let from = if index % 2 == 0 {
                "GET /api/docs [].id"
            } else {
                "GET /api/patients [].id"
            };
            split.add_vote(vote(
                &format!("s{}", index % 5),
                u64::from(index),
                Some(from),
            ));
        }
        assert!(!contradicts("doctor", &split, &map, Thresholds::default()));

        // Nine in ten from documents holds the share: that kind contradicts it.
        let mut documents = Evidence::default();
        for index in 0..20_u32 {
            let from = if index < 18 {
                "GET /api/docs [].id"
            } else {
                "GET /api/patients [].id"
            };
            documents.add_vote(vote(
                &format!("s{}", index % 5),
                u64::from(index),
                Some(from),
            ));
        }
        assert!(contradicts(
            "doctor",
            &documents,
            &map,
            Thresholds::default()
        ));
    }

    #[test]
    fn a_vote_counts_toward_a_kind_only_when_its_mapped_positions_agree() {
        let map = map();
        let mut evidence = Evidence::default();
        // Shown at a document and at a doctor position: the positions disagree.
        evidence.add_vote(Vote {
            slot: "GET /doctor/{id} path[1]".to_owned(),
            session: "a".to_owned(),
            day: 1,
            from: vec![
                "GET /api/docs [].id".to_owned(),
                "GET /api/appointments [].doc_id".to_owned(),
            ],
        });
        assert_eq!(evidence.votes(), 1);
        assert!(evidence.kinds(&map).is_empty());
        // Shown at a doctor position and at one the map does not name: a doctor.
        evidence.add_vote(Vote {
            slot: "GET /doctor/{id} path[1]".to_owned(),
            session: "b".to_owned(),
            day: 2,
            from: vec![
                "GET /api/other [].id".to_owned(),
                "GET /api/appointments [].doc_id".to_owned(),
            ],
        });
        assert_eq!(evidence.kinds(&map).get("doctor"), Some(&1));
    }

    #[test]
    fn an_anonymous_use_casts_no_vote_but_a_refusal_still_counts() {
        let mut anonymous = record(DecisionPath::FastAllow, Outcome::Allowed, Some(200));
        anonymous.session = String::new();
        assert!(observe(&anonymous).votes.is_empty());

        let mut refused = record(DecisionPath::JevDeny, Outcome::Blocked, Some(403));
        refused.session = String::new();
        assert_eq!(observe(&refused).denials.len(), 1);
    }

    #[test]
    fn a_position_unseen_for_thirty_days_is_retired() {
        assert!(!is_retired(100, 129));
        assert!(is_retired(100, 130));
        assert!(!is_retired(200, 100));
    }

    #[test]
    fn a_record_becomes_votes_only_when_the_origin_answered_2xx() {
        let allowed = record(DecisionPath::FastAllow, Outcome::Allowed, Some(200));
        let observed = observe(&allowed);
        assert_eq!(observed.votes.len(), 1);
        assert_eq!(observed.votes[0].session, "alice");
        assert_eq!(observed.votes[0].day, 3);
        assert_eq!(
            observed.votes[0].from,
            vec!["GET /api/appointments [].doc_id".to_owned()]
        );
        assert!(observed.denials.is_empty());

        // An origin error, a block, a would-block and a bypass are not uses.
        for (path, outcome, status) in [
            (DecisionPath::FastAllow, Outcome::Allowed, Some(404)),
            (DecisionPath::FastAllow, Outcome::Blocked, Some(200)),
            (DecisionPath::FastAllow, Outcome::WouldBlock, Some(200)),
            (DecisionPath::Bypass, Outcome::Allowed, Some(200)),
        ] {
            assert!(observe(&record(path, outcome, status)).votes.is_empty());
        }
    }

    #[test]
    fn a_jev_refusal_is_a_denial_even_in_observe_mode() {
        let refused = record(DecisionPath::JevDeny, Outcome::WouldBlock, Some(200));
        let observed = observe(&refused);
        assert!(observed.votes.is_empty());
        assert_eq!(observed.denials.len(), 1);
        assert_eq!(observed.denials[0].slot, "GET /doctor/{id} path[1]");
    }

    #[test]
    fn values_without_a_position_or_judged_inert_count_for_nothing() {
        let mut no_slot = record(DecisionPath::FastAllow, Outcome::Allowed, Some(200));
        no_slot.trace.values[0].slot = None;
        assert!(observe(&no_slot).votes.is_empty());
        let mut inert = record(DecisionPath::FastAllow, Outcome::Allowed, Some(200));
        inert.trace.values[0].inert = true;
        assert!(observe(&inert).votes.is_empty());
    }

    #[test]
    fn days_are_utc_days_from_the_epoch() {
        assert_eq!(day_of(0), 0);
        assert_eq!(day_of(DAY - 1), 0);
        assert_eq!(day_of(3 * DAY + 5), 3);
    }

    /// A decision record with one value at `GET /doctor/{id} path[1]`, shown by
    /// `GET /api/appointments` at `[].doc_id`, on day 3.
    fn record(path: DecisionPath, outcome: Outcome, status: Option<u16>) -> DecisionFacts {
        let trace = serde_json::json!({
            "v": 1,
            "values_truncated": false,
            "values": [{
                "at": "path[1]",
                "value": "7",
                "kind": "reference",
                "inert": false,
                "seen": true,
                "verified": true,
                "slot": "GET /doctor/{id} path[1]",
                "sources": [{
                    "field": "doc_id",
                    "request": "GET /api/appointments",
                    "slot": "GET /api/appointments [].doc_id"
                }]
            }],
            "timing": {"judge_ms": 1}
        });
        DecisionFacts {
            at_millis: 3 * DAY + 1_000,
            session: "alice".to_owned(),
            status,
            decision_path: path,
            outcome,
            trace: serde_json::from_value(trace).unwrap(),
        }
    }
}
