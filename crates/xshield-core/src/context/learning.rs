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
use super::objects::{ObjectMap, Reliability, Tier};
use super::trace::Trace;

/// Days of evidence a position is judged on.
pub const WINDOW_DAYS: u64 = 7;
/// Days a position may go unseen before it is retired.
pub const RETIRE_DAYS: u64 = 30;
/// Days a retired position is kept after its last use before the learning pass forgets it.
pub const KEEP_RETIRED_DAYS: u64 = 90;
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

    /// The response positions the votes were shown at, most votes first, ties by key.
    #[must_use]
    pub fn flows(&self) -> Vec<FlowShare> {
        let mut counts: BTreeMap<&str, (u32, BTreeSet<&str>)> = BTreeMap::new();
        for ((session, _), positions) in &self.votes {
            for position in positions.iter().collect::<BTreeSet<&String>>() {
                let entry = counts.entry(position.as_str()).or_default();
                entry.0 = entry.0.saturating_add(1);
                entry.1.insert(session.as_str());
            }
        }
        let mut flows: Vec<FlowShare> = counts
            .into_iter()
            .map(|(from, (votes, sessions))| FlowShare {
                from: from.to_owned(),
                votes,
                sessions: saturating_count(sessions.len()),
            })
            .collect();
        flows.sort_by(|left, right| {
            right
                .votes
                .cmp(&left.votes)
                .then_with(|| left.from.cmp(&right.from))
        });
        flows
    }

    /// The most recent day with a vote, when there is one.
    #[must_use]
    pub fn last_day(&self) -> Option<u64> {
        self.votes.keys().map(|(_, day)| *day).max()
    }

    /// One (session, response positions) pair per vote in the window, in session order.
    pub fn uses(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.votes
            .iter()
            .map(|((session, _), positions)| (session.as_str(), positions.as_slice()))
    }

    /// The sessions refused at this position in the window.
    #[must_use]
    pub fn refused_sessions(&self) -> BTreeSet<&str> {
        self.denials
            .iter()
            .map(|(session, _)| session.as_str())
            .collect()
    }
}

/// One response position a vote was shown at, with the votes and sessions it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowShare {
    /// The response position, `METHOD route location`.
    pub from: String,
    /// The votes whose value was shown at it.
    pub votes: u32,
    /// The distinct sessions among them.
    pub sessions: u32,
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

/// The share of votes, in thousandths, whose response position the map gives
/// `kind`. Zero when there are no votes.
#[must_use]
pub fn kind_share(evidence: &Evidence, map: &ObjectMap, kind: &str) -> u32 {
    let count = evidence.kinds(map).get(kind).copied().unwrap_or(0);
    share_of(count, evidence.votes())
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

/// A response position is `self` when at most this share of its values, in thousandths,
/// is seen by two units or more: its units see nearly disjoint objects.
pub const SELF_SHARE_MAX_PER_MILLE: u32 = 10;
/// A request position rarely sends public values when at most this share of its judged
/// votes, in thousandths, came from public positions only.
pub const RARE_PUBLIC_PER_MILLE: u32 = 10;
/// A request position commonly sends public values when at least this share of its
/// judged votes, in thousandths, came from public positions only.
pub const COMMON_PUBLIC_PER_MILLE: u32 = 200;
/// Agreement, in thousandths, a `high` tier needs from nearly every value.
const HIGH_AGREEMENT_PER_MILLE: u32 = 980;

/// What the control plane counted at one response position. The units are the user
/// identities the site declares, or the sessions when it declares none. A value is one
/// fingerprint: the same value fingerprints alike in every record, so counting the units
/// that saw a fingerprint counts the units that saw the value.
///
/// The records keep at most eight fingerprints per position, the smallest. A value that a
/// unit's list did not keep may still have been seen by another unit, so a value seen by one
/// unit is evidence of `self` only when no other unit's record at the position was full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponseStats {
    /// Whether the units are user identities rather than sessions.
    pub identified: bool,
    /// Non-admin units that got a 2xx carrying values at the position.
    pub units: u32,
    /// Distinct fingerprints those units saw at the position, however many units saw each.
    pub values: u32,
    /// Of `values`, the ones two or more units saw. Such a count is real sharing.
    pub shared: u32,
    /// Of `values`, the ones exactly one unit saw while every other unit's records at the
    /// position were complete, so no other unit could have seen them unkept.
    pub complete_single: u32,
    /// Admin units that got a 2xx at the position.
    pub admin_units: u32,
    /// Non-admin units refused at the position (no 2xx).
    pub refused_units: u32,
}

/// The tier the rules give a response position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierJudgement {
    /// Whose objects the position shows.
    pub tier: Tier,
    /// How sure the rules are.
    pub reliability: Reliability,
    /// The share of values, in thousandths, that agree with the tier: the shared ones for
    /// `public`, the unshared ones for `self`. Zero for `admin`, which the refusals decide.
    pub agreement_per_mille: u32,
}

/// The tier the rules give a response position, when they can tell it and the answer is
/// reliable enough to propose.
///
/// `admin`: only admin units get values back, and the non-admin units that tried were
/// refused. `public`: the non-admin units share nearly all their values. `self`: they share
/// nearly none. Anything between is left to the learning agent, and so is `org`, which
/// needs the organisation of each unit. Too little evidence gives no judgement.
///
/// Without identities the units are sessions, and one user's sessions look like several
/// users, so the reliability drops one step. A judgement that drops below `medium` is not
/// returned.
#[must_use]
pub fn judge_tier(stats: &ResponseStats, thresholds: Thresholds) -> Option<TierJudgement> {
    if stats.admin_units > 0 && stats.units == 0 && stats.refused_units >= thresholds.sessions {
        let strong = stats.refused_units >= doubled(thresholds.sessions);
        let reliability = grade(strong, stats.identified)?;
        return Some(TierJudgement {
            tier: Tier::Admin,
            reliability,
            agreement_per_mille: 0,
        });
    }
    if stats.units < thresholds.sessions {
        return None;
    }
    let (tier, agreement) = match public_agreement(stats, thresholds) {
        Some(agreement) => (Tier::Public, agreement),
        None => (Tier::Own, own_agreement(stats, thresholds)?),
    };
    let strong =
        stats.units >= doubled(thresholds.sessions) && agreement >= HIGH_AGREEMENT_PER_MILLE;
    let reliability = grade(strong, stats.identified)?;
    Some(TierJudgement {
        tier,
        reliability,
        agreement_per_mille: agreement,
    })
}

/// The agreement of `public`: the share of values, in thousandths, that two or more units
/// saw, when the position has enough values and the share reaches the threshold. Values
/// seen by one unit only, which may have been kept off other lists, dilute the share on
/// purpose: they are not counted for `public`.
fn public_agreement(stats: &ResponseStats, thresholds: Thresholds) -> Option<u32> {
    if stats.values < thresholds.votes {
        return None;
    }
    let shared = share_of(stats.shared, stats.values);
    (shared >= thresholds.share_per_mille).then_some(shared)
}

/// The agreement of `self`: the share, in thousandths, of the values the rules can decide
/// (those two or more units saw, and those one unit saw with complete records around them)
/// that nobody else saw. Needs enough complete single-unit values, and at most the self
/// share of the decided ones shared.
fn own_agreement(stats: &ResponseStats, thresholds: Thresholds) -> Option<u32> {
    if stats.complete_single < thresholds.votes {
        return None;
    }
    let decided = stats.shared.saturating_add(stats.complete_single);
    let shared = share_of(stats.shared, decided);
    (shared <= SELF_SHARE_MAX_PER_MILLE).then_some(1_000 - shared)
}

/// What the rules give a request position: whether normal traffic sends values from public
/// positions to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptJudgement {
    /// `false`: normal traffic rarely sends public values here. `true`: it commonly does.
    pub accepts_public: bool,
    /// How sure the rules are.
    pub reliability: Reliability,
    /// The votes judged: those with at least one response position of a known tier.
    pub votes: u32,
    /// The distinct sessions among them.
    pub sessions: u32,
    /// The share of judged votes, in thousandths, whose values came from public positions only.
    pub public_per_mille: u32,
}

/// Whether a request position accepts public sources, from its votes and the confirmed tiers
/// of the response positions the votes were shown at.
///
/// A vote is judged when at least one of its response positions has a tier, and it counts as
/// public when every such position is `public`. Votes of admin sessions are left out: an
/// admin's use of public objects says nothing about ordinary users. So are votes of sessions
/// refused at the position, since a refused session is what the judge is there to stop.
///
/// Without identities the sessions count as users, so the reliability drops one step.
#[must_use]
pub fn judge_accepts_public(
    evidence: &Evidence,
    tier_of: impl Fn(&str) -> Option<Tier>,
    admin_sessions: &BTreeSet<String>,
    identified: bool,
    thresholds: Thresholds,
) -> Option<AcceptJudgement> {
    let refused = evidence.refused_sessions();
    let mut votes = 0_u32;
    let mut public = 0_u32;
    let mut sessions = BTreeSet::new();
    for (session, positions) in evidence.uses() {
        if admin_sessions.contains(session) || refused.contains(session) {
            continue;
        }
        let mut tiers = positions
            .iter()
            .filter_map(|position| tier_of(position.as_str()))
            .peekable();
        if tiers.peek().is_none() {
            continue;
        }
        votes = votes.saturating_add(1);
        sessions.insert(session);
        if tiers.all(|tier| tier == Tier::Public) {
            public = public.saturating_add(1);
        }
    }
    let sessions = saturating_count(sessions.len());
    if votes < thresholds.votes || sessions < thresholds.sessions {
        return None;
    }
    let public_per_mille = share_of(public, votes);
    let accepts_public = if public_per_mille <= RARE_PUBLIC_PER_MILLE {
        false
    } else if public_per_mille >= COMMON_PUBLIC_PER_MILLE {
        true
    } else {
        return None;
    };
    let margin = if accepts_public {
        public_per_mille >= doubled(COMMON_PUBLIC_PER_MILLE)
    } else {
        doubled(public_per_mille) <= RARE_PUBLIC_PER_MILLE
    };
    let strong =
        margin && votes >= doubled(thresholds.votes) && sessions >= doubled(thresholds.sessions);
    let reliability = grade(strong, identified)?;
    Some(AcceptJudgement {
        accepts_public,
        reliability,
        votes,
        sessions,
        public_per_mille,
    })
}

/// The reliability of a judgement: `high` when the evidence is strong, `medium` when it only
/// meets the thresholds. Without identities, one step lower. `None` for `low`, which is
/// never proposed.
fn grade(strong: bool, identified: bool) -> Option<Reliability> {
    let base = if strong {
        Reliability::High
    } else {
        Reliability::Medium
    };
    let reliability = match (base, identified) {
        (Reliability::High, false) => Reliability::Medium,
        (Reliability::Medium, false) | (Reliability::Low, _) => Reliability::Low,
        (level, true) => level,
    };
    (reliability != Reliability::Low).then_some(reliability)
}

fn doubled(count: u32) -> u32 {
    count.saturating_mul(2)
}

#[cfg(test)]
mod tier_tests {
    use super::*;
    use std::collections::BTreeSet;

    const PATIENTS: &str = "GET /api/patients [].id";
    const SEARCH: &str = "GET /api/search [].id";
    const DELETE: &str = "DELETE /api/patients/{id} path[1]";

    fn thresholds() -> Thresholds {
        Thresholds::default()
    }

    fn tiers(key: &str) -> Option<Tier> {
        match key {
            PATIENTS => Some(Tier::Own),
            SEARCH => Some(Tier::Public),
            _ => None,
        }
    }

    /// Stats for `units` non-admin identities that saw `values` values, `shared` of them
    /// by two units or more.
    fn stats(units: u32, values: u32, shared: u32) -> ResponseStats {
        ResponseStats {
            identified: true,
            units,
            values,
            shared,
            ..ResponseStats::default()
        }
    }

    /// Stats for `units` identities whose `values` values were each seen by one unit only,
    /// with complete records around them.
    fn own_stats(units: u32, values: u32) -> ResponseStats {
        ResponseStats {
            identified: true,
            units,
            values,
            complete_single: values,
            ..ResponseStats::default()
        }
    }

    #[test]
    fn single_unit_values_count_for_self_only_when_records_were_complete() {
        // Thirty values seen by one unit each, but another unit's full record may have
        // kept some of them back: no evidence either way.
        let truncated = ResponseStats {
            identified: true,
            units: 10,
            values: 30,
            complete_single: 0,
            ..ResponseStats::default()
        };
        assert_eq!(judge_tier(&truncated, thresholds()), None);
    }

    #[test]
    fn sharing_among_the_decided_values_blocks_self() {
        // One value of 31 decided values is seen by two units: 32 per mille, above the
        // self limit, and far below the public share.
        let shared_one = ResponseStats {
            identified: true,
            units: 10,
            values: 31,
            shared: 1,
            complete_single: 30,
            ..ResponseStats::default()
        };
        assert_eq!(judge_tier(&shared_one, thresholds()), None);
    }

    #[test]
    fn values_all_seen_by_many_identities_are_public_and_high() {
        let judged = judge_tier(&stats(12, 40, 40), thresholds()).unwrap();
        assert_eq!(judged.tier, Tier::Public);
        assert_eq!(judged.reliability, Reliability::High);
        assert_eq!(judged.agreement_per_mille, 1_000);
    }

    #[test]
    fn sessions_instead_of_identities_drop_reliability_one_step() {
        let mut unidentified = stats(12, 40, 40);
        unidentified.identified = false;
        let judged = judge_tier(&unidentified, thresholds()).unwrap();
        assert_eq!(judged.tier, Tier::Public);
        assert_eq!(judged.reliability, Reliability::Medium);
    }

    #[test]
    fn disjoint_units_are_self_and_high_only_with_enough_units() {
        let few = judge_tier(&own_stats(6, 30), thresholds()).unwrap();
        assert_eq!(few.tier, Tier::Own);
        assert_eq!(few.reliability, Reliability::Medium);
        let many = judge_tier(&own_stats(10, 30), thresholds()).unwrap();
        assert_eq!(many.reliability, Reliability::High);
        assert_eq!(many.agreement_per_mille, 1_000);
    }

    #[test]
    fn a_mixed_share_is_left_to_the_agent() {
        // Half the values shared: neither public nor self, and org needs the organisation.
        assert_eq!(judge_tier(&stats(8, 40, 20), thresholds()), None);
    }

    #[test]
    fn too_little_evidence_gives_no_tier() {
        assert_eq!(judge_tier(&stats(4, 40, 40), thresholds()), None);
        assert_eq!(judge_tier(&stats(12, 10, 10), thresholds()), None);
    }

    #[test]
    fn a_weak_judgement_without_identities_is_not_returned() {
        let mut weak = own_stats(6, 30);
        weak.identified = false;
        assert_eq!(judge_tier(&weak, thresholds()), None);
    }

    #[test]
    fn only_admin_units_get_values_back_and_the_others_are_refused() {
        let admin = ResponseStats {
            identified: true,
            admin_units: 1,
            refused_units: 5,
            ..ResponseStats::default()
        };
        let judged = judge_tier(&admin, thresholds()).unwrap();
        assert_eq!(judged.tier, Tier::Admin);
        assert_eq!(judged.reliability, Reliability::Medium);

        let strong = ResponseStats {
            refused_units: 10,
            ..admin
        };
        assert_eq!(
            judge_tier(&strong, thresholds()).map(|judged| judged.reliability),
            Some(Reliability::High)
        );
    }

    #[test]
    fn admin_values_seen_by_ordinary_units_are_not_admin() {
        let shared_with_admin = ResponseStats {
            admin_units: 1,
            refused_units: 10,
            units: 1,
            values: 1,
            ..ResponseStats::default()
        };
        assert_eq!(judge_tier(&shared_with_admin, thresholds()), None);
    }

    /// Votes for `DELETE` from `sessions` sessions: each vote shows its value at `from`, and
    /// the sessions, days and votes are spread so that none collapses into another.
    fn uses(count: u64, sessions: u64, from: impl Fn(u64) -> Vec<&'static str>) -> Evidence {
        let mut evidence = Evidence::default();
        for index in 0..count {
            evidence.add_vote(Vote {
                slot: DELETE.to_owned(),
                session: format!("s{}", index % sessions),
                day: index / sessions,
                from: from(index).into_iter().map(str::to_owned).collect(),
            });
        }
        evidence
    }

    fn no_admins() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn a_request_that_only_takes_own_values_rarely_takes_public_ones() {
        let evidence = uses(40, 10, |_| vec![PATIENTS]);
        let judged =
            judge_accepts_public(&evidence, tiers, &no_admins(), true, thresholds()).unwrap();
        assert!(!judged.accepts_public);
        assert_eq!(judged.reliability, Reliability::High);
        assert_eq!(judged.public_per_mille, 0);
    }

    #[test]
    fn a_request_that_mostly_takes_public_values_accepts_them() {
        let evidence = uses(40, 10, |_| vec![SEARCH]);
        let judged =
            judge_accepts_public(&evidence, tiers, &no_admins(), true, thresholds()).unwrap();
        assert!(judged.accepts_public);
        assert_eq!(judged.public_per_mille, 1_000);
        assert_eq!(judged.reliability, Reliability::High);
    }

    #[test]
    fn a_middle_share_gives_no_acceptance() {
        // 4 of 40 judged votes (100 per mille) took public values: neither rare nor common.
        let evidence = uses(40, 10, |index| {
            if index < 4 {
                vec![SEARCH]
            } else {
                vec![PATIENTS]
            }
        });
        assert_eq!(
            judge_accepts_public(&evidence, tiers, &no_admins(), true, thresholds()),
            None
        );
    }

    #[test]
    fn a_vote_mixing_own_and_public_values_is_not_public() {
        let evidence = uses(40, 10, |_| vec![SEARCH, PATIENTS]);
        let judged =
            judge_accepts_public(&evidence, tiers, &no_admins(), true, thresholds()).unwrap();
        assert!(!judged.accepts_public);
        assert_eq!(judged.public_per_mille, 0);
    }

    #[test]
    fn an_admin_session_taking_public_values_does_not_count() {
        // Sessions s0 and s1 are admins and take public values; the rest take their own.
        let evidence = uses(40, 10, |index| {
            if index % 10 < 2 {
                vec![SEARCH]
            } else {
                vec![PATIENTS]
            }
        });
        let admins: BTreeSet<String> = ["s0", "s1"].iter().map(|s| (*s).to_owned()).collect();
        let judged = judge_accepts_public(&evidence, tiers, &admins, true, thresholds()).unwrap();
        assert!(!judged.accepts_public);
        assert_eq!(judged.sessions, 8);
        assert_eq!(judged.public_per_mille, 0);
    }

    #[test]
    fn a_refused_session_taking_public_values_does_not_count() {
        // Sessions s0 and s1 take public values, but Jev refused them at this position.
        let mut evidence = uses(40, 10, |index| {
            if index % 10 < 2 {
                vec![SEARCH]
            } else {
                vec![PATIENTS]
            }
        });
        for session in ["s0", "s1"] {
            evidence.add_denial(Denial {
                slot: DELETE.to_owned(),
                session: session.to_owned(),
                day: 0,
            });
        }
        let judged =
            judge_accepts_public(&evidence, tiers, &no_admins(), true, thresholds()).unwrap();
        assert!(!judged.accepts_public);
        assert_eq!(judged.sessions, 8);
        assert_eq!(judged.public_per_mille, 0);
    }

    #[test]
    fn values_of_unknown_tier_are_not_judged() {
        let evidence = uses(40, 10, |_| vec!["GET /unknown [].id"]);
        assert_eq!(
            judge_accepts_public(&evidence, tiers, &no_admins(), true, thresholds()),
            None
        );
    }

    #[test]
    fn without_identities_the_acceptance_drops_one_step() {
        let evidence = uses(40, 10, |_| vec![PATIENTS]);
        let judged =
            judge_accepts_public(&evidence, tiers, &no_admins(), false, thresholds()).unwrap();
        assert!(!judged.accepts_public);
        assert_eq!(judged.reliability, Reliability::Medium);
    }
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
    fn the_kind_share_counts_the_votes_from_positions_of_that_kind() {
        let map = map();
        let mut mixed = evidence(18, 5, Some("GET /api/appointments [].doc_id"));
        for index in 0..2 {
            mixed.add_vote(vote(
                &format!("x{index}"),
                50 + index,
                Some("GET /api/docs [].id"),
            ));
        }
        assert_eq!(kind_share(&mixed, &map, "doctor"), 900);
        assert_eq!(kind_share(&mixed, &map, "document"), 100);
        assert_eq!(kind_share(&Evidence::default(), &map, "doctor"), 0);
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
