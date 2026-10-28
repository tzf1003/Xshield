//! Site-level observe → enforce rollout (docs/32).
//!
//! A site is enforced unless its approved configuration explicitly says
//! otherwise. In observe mode, until a fixed deadline, a read-only request
//! that the deterministic rules would refuse is still forwarded and audited as
//! `OBSERVED_WOULD_DENY`; every other refusal stays a refusal. Routes can be
//! tightened back to enforce one at a time, never the other way round: the
//! block only lists routes to enforce. Nothing a client sends selects or
//! changes the mode.

use super::{SecurityEntry, SiteRouteConfig};
use crate::domain::InvalidValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// [`InvalidValue`] field for an incoherent rollout block.
pub const ROLLOUT_INVALID: &str = "site_rollout";

/// Longest observe window a configuration may request, counted from when it
/// is saved: thirty days.
pub const MAX_OBSERVE_WINDOW_SECONDS: u64 = 30 * 24 * 3_600;

/// How long before the deadline the control plane starts warning.
pub const EXPIRY_WARNING_SECONDS: u64 = 24 * 3_600;

/// Whether deterministic refusals are enforced or only observed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RolloutMode {
    /// Every refusal is enforced. The default, and what any missing or
    /// unparseable block means.
    #[default]
    Enforce,
    /// Read-only refusals outside `PUBLIC` routes are forwarded and audited.
    Observe,
}

/// The rollout block of a site policy.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteRollout {
    #[serde(default)]
    pub mode: RolloutMode,
    /// Observe ends at this UTC second; after it the site is enforced without
    /// any configuration change. Required in observe mode, absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_until_unix: Option<u64>,
    /// Label of this observe window, written to every `OBSERVED_WOULD_DENY`
    /// event as `rollout_revision`. Required in observe mode, empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revision: String,
    /// Routes already verified and enforced while the rest of the site is
    /// observed. Only meaningful, and only allowed, in observe mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enforced_operations: Vec<String>,
}

impl SiteRollout {
    /// Whether this is the default enforced block, which is not serialized so
    /// that configurations without a rollout keep their exact bytes.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Validates the block against the operation IDs of its policy.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] named [`ROLLOUT_INVALID`] when the block is
    /// incoherent.
    pub fn validate<'a>(
        &self,
        operation_ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), InvalidValue> {
        let invalid = || InvalidValue::new(ROLLOUT_INVALID);
        match self.mode {
            RolloutMode::Enforce => {
                if self.is_default() {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            RolloutMode::Observe => {
                if self.observe_until_unix.is_none_or(|until| until == 0)
                    || !valid_revision(&self.revision)
                {
                    return Err(invalid());
                }
                let known = operation_ids.into_iter().collect::<BTreeSet<_>>();
                let mut seen = BTreeSet::new();
                for operation in &self.enforced_operations {
                    if !known.contains(operation.as_str()) || !seen.insert(operation.as_str()) {
                        return Err(invalid());
                    }
                }
                Ok(())
            }
        }
    }

    /// Checks the observe deadline against the time a configuration is saved:
    /// it must lie in the future and at most [`MAX_OBSERVE_WINDOW_SECONDS`]
    /// ahead. An enforced block always passes.
    ///
    /// # Errors
    /// Returns [`InvalidValue`] named [`ROLLOUT_INVALID`] otherwise.
    pub fn validate_window(&self, now_unix: u64) -> Result<(), InvalidValue> {
        match (self.mode, self.observe_until_unix) {
            (RolloutMode::Enforce, _) => Ok(()),
            (RolloutMode::Observe, Some(until))
                if until > now_unix && until - now_unix <= MAX_OBSERVE_WINDOW_SECONDS =>
            {
                Ok(())
            }
            (RolloutMode::Observe, _) => Err(InvalidValue::new(ROLLOUT_INVALID)),
        }
    }

    /// Whether the site is in its observe window at `now_unix`.
    #[must_use]
    pub fn observing(&self, now_unix: u64) -> bool {
        self.mode == RolloutMode::Observe
            && self
                .observe_until_unix
                .is_some_and(|until| now_unix < until)
    }

    /// Whether a refusal on `route` may be forwarded as observed at
    /// `now_unix`: the site is observing, the route is not enforced on its
    /// own, is not `PUBLIC`, and is read-only.
    #[must_use]
    pub fn observes(&self, route: &SiteRouteConfig, now_unix: u64) -> bool {
        self.observing(now_unix)
            && route.security_entry != SecurityEntry::Public
            && matches!(route.method.as_str(), "GET" | "HEAD")
            && !self.enforced_operations.contains(&route.operation_id)
    }

    /// Whether the observe deadline is less than a day away at `now_unix`
    /// (and not yet passed): the control plane warns from then on.
    #[must_use]
    pub fn expiry_imminent(&self, now_unix: u64) -> bool {
        self.observing(now_unix)
            && self
                .observe_until_unix
                .is_some_and(|until| until - now_unix <= EXPIRY_WARNING_SECONDS)
    }

    /// Whether going from `before` to `self` widens what is observed: from
    /// enforce to observe, a later deadline, or a route no longer enforced.
    /// `before` is `None` when nothing is served, which counts as enforce.
    #[must_use]
    pub fn relaxes(&self, before: Option<&Self>) -> bool {
        if self.mode != RolloutMode::Observe {
            return false;
        }
        let Some(before) = before.filter(|before| before.mode == RolloutMode::Observe) else {
            return true;
        };
        self.observe_until_unix > before.observe_until_unix
            || before
                .enforced_operations
                .iter()
                .any(|operation| !self.enforced_operations.contains(operation))
    }
}

/// The same alphabet and bounds as a `policy_revision` label.
fn valid_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn observe(until: u64) -> SiteRollout {
        SiteRollout {
            mode: RolloutMode::Observe,
            observe_until_unix: Some(until),
            revision: "rollout-1".to_owned(),
            enforced_operations: Vec::new(),
        }
    }

    fn route(operation: &str, method: &str, entry: SecurityEntry) -> SiteRouteConfig {
        SiteRouteConfig {
            operation_id: operation.to_owned(),
            method: method.to_owned(),
            path: "/x".to_owned(),
            security_entry: entry,
            source_action: None,
            resource_type: None,
            view_profile: None,
            resource_query_parameter: None,
            resource_path_parameter: None,
            request_crypto: None,
            response_crypto: None,
            response_mode: String::new(),
            max_response_bytes: 1_048_576,
            auth_binding: None,
            auth_revoke: None,
            sensor_html: None,
            page_actions: None,
            issued_by: None,
            resource_grant: None,
            query_pagination: None,
            share_issue: None,
            auth_refresh: None,
            auth_context_switch: None,
        }
    }

    #[test]
    fn a_missing_block_is_enforce_and_serializes_to_nothing() {
        let rollout: SiteRollout = serde_json::from_str("{}").unwrap();
        assert_eq!(rollout.mode, RolloutMode::Enforce);
        assert!(rollout.is_default());
        assert!(rollout.validate([]).is_ok());
        assert!(!rollout.observing(NOW));
        for unknown in [
            r#"{"mode":"OBSERVE"}"#,
            r#"{"mode":"monitor"}"#,
            r#"{"mode":null}"#,
            r#"{"mode":"observe","extra":1}"#,
        ] {
            assert!(
                serde_json::from_str::<SiteRollout>(unknown).is_err(),
                "{unknown}"
            );
        }
    }

    #[test]
    fn enforce_carries_no_observe_fields() {
        for rollout in [
            SiteRollout {
                observe_until_unix: Some(NOW),
                ..SiteRollout::default()
            },
            SiteRollout {
                revision: "r1".to_owned(),
                ..SiteRollout::default()
            },
            SiteRollout {
                enforced_operations: vec!["a".to_owned()],
                ..SiteRollout::default()
            },
        ] {
            assert!(rollout.validate(["a"]).is_err(), "{rollout:?}");
        }
    }

    #[test]
    fn observe_needs_a_deadline_a_label_and_known_distinct_routes() {
        assert!(observe(NOW).validate(["a"]).is_ok());
        let mut rollout = observe(NOW);
        rollout.observe_until_unix = None;
        assert!(rollout.validate(["a"]).is_err());
        rollout.observe_until_unix = Some(0);
        assert!(rollout.validate(["a"]).is_err());
        for label in ["", "has space", "a/b", &"r".repeat(129)] {
            let mut rollout = observe(NOW);
            rollout.revision = label.to_owned();
            assert!(rollout.validate(["a"]).is_err(), "{label}");
        }
        let mut rollout = observe(NOW);
        rollout.enforced_operations = vec!["a".to_owned()];
        assert!(rollout.validate(["a", "b"]).is_ok());
        rollout.enforced_operations = vec!["missing".to_owned()];
        assert!(rollout.validate(["a", "b"]).is_err());
        rollout.enforced_operations = vec!["a".to_owned(), "a".to_owned()];
        assert!(rollout.validate(["a", "b"]).is_err());
    }

    #[test]
    fn the_window_is_in_the_future_and_bounded() {
        assert!(SiteRollout::default().validate_window(NOW).is_ok());
        assert!(observe(NOW + 1).validate_window(NOW).is_ok());
        assert!(
            observe(NOW + MAX_OBSERVE_WINDOW_SECONDS)
                .validate_window(NOW)
                .is_ok()
        );
        assert!(observe(NOW).validate_window(NOW).is_err());
        assert!(observe(NOW - 1).validate_window(NOW).is_err());
        assert!(
            observe(NOW + MAX_OBSERVE_WINDOW_SECONDS + 1)
                .validate_window(NOW)
                .is_err()
        );
    }

    #[test]
    fn only_read_only_non_public_unenforced_routes_are_observed_before_the_deadline() {
        let mut rollout = observe(NOW + 100);
        rollout.enforced_operations = vec!["verified".to_owned()];
        let ui = SecurityEntry::UiActionRequired;
        assert!(rollout.observes(&route("list", "GET", ui), NOW));
        assert!(rollout.observes(&route("list", "HEAD", ui), NOW));
        assert!(!rollout.observes(&route("save", "POST", ui), NOW));
        assert!(!rollout.observes(&route("drop", "DELETE", ui), NOW));
        assert!(!rollout.observes(&route("docs", "GET", SecurityEntry::Public), NOW));
        assert!(!rollout.observes(&route("verified", "GET", ui), NOW));
        assert!(!rollout.observes(&route("list", "GET", ui), NOW + 100));
        assert!(!SiteRollout::default().observes(&route("list", "GET", ui), NOW));
    }

    #[test]
    fn the_expiry_warning_starts_a_day_before_the_deadline() {
        let rollout = observe(NOW + EXPIRY_WARNING_SECONDS + 1);
        assert!(!rollout.expiry_imminent(NOW));
        assert!(rollout.expiry_imminent(NOW + 1));
        assert!(!rollout.expiry_imminent(NOW + EXPIRY_WARNING_SECONDS + 1));
        assert!(!SiteRollout::default().expiry_imminent(NOW));
    }

    #[test]
    fn relaxing_is_entering_observe_extending_it_or_releasing_a_route() {
        let enforce = SiteRollout::default();
        let base = observe(NOW + 100);
        assert!(base.relaxes(None));
        assert!(base.relaxes(Some(&enforce)));
        assert!(!enforce.relaxes(Some(&base)));
        assert!(!enforce.relaxes(None));
        assert!(!base.relaxes(Some(&base)));
        assert!(observe(NOW + 101).relaxes(Some(&base)));
        assert!(!observe(NOW + 99).relaxes(Some(&base)));
        let mut tightened = base.clone();
        tightened.enforced_operations = vec!["a".to_owned()];
        assert!(!tightened.relaxes(Some(&base)));
        assert!(base.relaxes(Some(&tightened)));
        let mut relabelled = base.clone();
        relabelled.revision = "rollout-2".to_owned();
        assert!(!relabelled.relaxes(Some(&base)));
    }
}
