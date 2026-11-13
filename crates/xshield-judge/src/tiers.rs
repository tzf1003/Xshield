//! What the site's tiers say about the responses that showed a request value
//! (docs/01 section 1.4, step 4; docs/07 section 7.4.7).
//!
//! A response position may say who its data is for (`tier`), and a request
//! position may say whether it takes a value that only a public response showed
//! (`accepts_public`). A public response, such as a search over every record,
//! shows the value to any logged-in session, so it proves no right to the object.
//! Where the request position takes no such value and both sides are sure of
//! their reading, a value whose every source is such a public response is an
//! attempt to act on an object the session has no right to. It goes to Jev marked
//! as an attempt; the gateway never allows it on its own.
//!
//! An administrator's listing proves a value to an administrator session only, as an
//! ordinary response does; the session's role is read from its identity (docs/07 section
//! 7.4.7). A response the map labels `self` proves a value as an untiered one does, and a
//! value that such a response shows is never an attempt. A site without tiers is judged as
//! it always was: every origin that shows the value as the request's kind of object proves it.

use xshield_core::context::{Attempt, ObjectMap, PublicAccess, Reliability, Tier, tier_proves};

use crate::context::Origin;
use crate::slots::origin_tier;

/// What the tiers make of one request value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Judged {
    /// A response the tiers allow to prove a right showed the value as the
    /// request's kind of object.
    pub verified: bool,
    /// The value is an attempt: every source of it is a public response the map
    /// is sure of, and the request position takes no public source the map is
    /// sure of.
    pub attempt: Option<Attempt>,
}

/// Judges one request value. `sources` is every origin the session has for the
/// value, `shown` the origins that show it as the request's kind of object (see
/// `Seen::shown_origins`), `access` is what the map says of the request position,
/// and `admin` is whether the session is an administrator.
#[must_use]
pub fn judge(
    sources: &[&Origin],
    shown: &[&Origin],
    access: Option<PublicAccess>,
    objects: &ObjectMap,
    admin: bool,
) -> Judged {
    let closed =
        access.is_some_and(|access| !access.accepts && access.reliability == Reliability::High);
    let verified = shown
        .iter()
        .any(|origin| tier_proves(origin_tier(objects, origin), closed, admin));
    let public_only = closed
        && !sources.is_empty()
        && sources
            .iter()
            .all(|origin| origin_tier(objects, origin) == Some((Tier::Public, Reliability::High)));
    Judged {
        verified,
        attempt: public_only.then_some(Attempt::OverPrivilege),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slots::request_access;

    const TIERED: &str = r#"{
        "classes": [{"id": "patient", "name": "患者"}],
        "slots": [
            {"key": "GET /api/search results[].id", "class": "patient", "source": "admin", "tier": "public", "reliability": "high"},
            {"key": "GET /api/search/low results[].id", "class": "patient", "source": "admin", "tier": "public", "reliability": "low"},
            {"key": "GET /api/patients patients[].id", "class": "patient", "source": "admin", "tier": "self", "reliability": "high"},
            {"key": "GET /api/admin/patients patients[].id", "class": "patient", "source": "admin", "tier": "admin", "reliability": "high"},
            {"key": "GET /api/org/patients patients[].id", "class": "patient", "source": "admin", "tier": "org", "reliability": "high"},
            {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "admin", "accepts_public": false, "reliability": "high"},
            {"key": "DELETE /api/records/{id} path[2]", "class": "patient", "source": "admin", "accepts_public": false, "reliability": "low"},
            {"key": "POST /api/patients/{id}/notes path[2]", "class": "patient", "source": "admin", "accepts_public": true, "reliability": "high"},
            {"key": "GET /api/search/none results[].id", "class": "patient", "source": "admin", "tier": "public"},
            {"key": "GET /api/mine patients[].id", "class": "patient", "source": "admin", "tier": "self"},
            {"key": "PUT /api/notes/{id} path[2]", "class": "patient", "source": "admin", "accepts_public": false}
        ]
    }"#;

    fn map(text: &str) -> ObjectMap {
        serde_json::from_str(text).expect("the test map is valid")
    }

    fn origin(request: &str, at: &str) -> Origin {
        Origin {
            field: "id".to_owned(),
            at: at.to_owned(),
            request: request.to_owned(),
            request_id: 1,
            at_ms: 1,
        }
    }

    const SEARCH: (&str, &str) = ("GET /api/search", "results[].id");
    const SEARCH_LOW: (&str, &str) = ("GET /api/search/low", "results[].id");
    const SEARCH_UNRATED: (&str, &str) = ("GET /api/search/none", "results[].id");
    const OWN: (&str, &str) = ("GET /api/patients", "patients[].id");
    const OWN_UNRATED: (&str, &str) = ("GET /api/mine", "patients[].id");
    const ADMIN: (&str, &str) = ("GET /api/admin/patients", "patients[].id");
    const ORG: (&str, &str) = ("GET /api/org/patients", "patients[].id");
    const UNTIERED: (&str, &str) = ("GET /api/other", "items[].id");

    /// A request position closed to public sources, and the map is sure of it.
    const CLOSED: Option<PublicAccess> = Some(PublicAccess {
        accepts: false,
        reliability: Reliability::High,
    });

    fn sightings(parts: &[(&str, &str)]) -> Vec<Origin> {
        parts
            .iter()
            .map(|(request, at)| origin(request, at))
            .collect()
    }

    fn refs(origins: &[Origin]) -> Vec<&Origin> {
        origins.iter().collect()
    }

    #[test]
    fn a_public_sighting_does_not_prove_a_write_that_takes_no_public_source() {
        let objects = map(TIERED);
        let search = sightings(&[SEARCH]);
        assert_eq!(
            judge(&refs(&search), &refs(&search), CLOSED, &objects, false),
            Judged {
                verified: false,
                attempt: Some(Attempt::OverPrivilege),
            }
        );
    }

    #[test]
    fn a_public_sighting_still_proves_a_position_that_takes_public_sources() {
        let objects = map(TIERED);
        let search = sightings(&[SEARCH]);
        let accepts = Some(PublicAccess {
            accepts: true,
            reliability: Reliability::High,
        });
        assert_eq!(
            judge(&refs(&search), &refs(&search), accepts, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }

    #[test]
    fn a_weak_judgement_on_either_side_does_not_tighten() {
        let objects = map(TIERED);
        // A weak position is not closed, so the sure public sighting proves the value.
        let search = sightings(&[SEARCH]);
        let weak_position = Some(PublicAccess {
            accepts: false,
            reliability: Reliability::Low,
        });
        assert_eq!(
            judge(
                &refs(&search),
                &refs(&search),
                weak_position,
                &objects,
                false
            ),
            Judged {
                verified: true,
                attempt: None,
            }
        );
        // A weak public sighting proves the value even where the position is closed.
        let weak_tier = sightings(&[SEARCH_LOW]);
        assert_eq!(
            judge(
                &refs(&weak_tier),
                &refs(&weak_tier),
                CLOSED,
                &objects,
                false
            ),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }

    #[test]
    fn a_source_the_map_does_not_classify_keeps_the_status_quo() {
        let objects = map(TIERED);
        // The value is also seen in a response the map leaves unclassified, so it is not
        // only public: it is not verified by the public sighting, and it is no attempt.
        let sources = sightings(&[SEARCH, UNTIERED]);
        let shown = sightings(&[SEARCH]);
        assert_eq!(
            judge(&refs(&sources), &refs(&shown), CLOSED, &objects, false),
            Judged {
                verified: false,
                attempt: None,
            }
        );
    }

    #[test]
    fn a_self_sighting_proves_the_value_and_keeps_it_from_tightening() {
        let objects = map(TIERED);
        // The session's own record shows the value: it is verified, as an untiered response would
        // show it, so no Jev call is needed for it.
        let own = sightings(&[OWN]);
        assert_eq!(
            judge(&refs(&own), &refs(&own), CLOSED, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
        // Beside a public sighting, the own record keeps the value from being an attempt, and it
        // proves the value too.
        let sources = sightings(&[SEARCH, OWN]);
        assert_eq!(
            judge(&refs(&sources), &refs(&sources), CLOSED, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }

    #[test]
    fn an_org_sighting_proves_the_value_as_it_did_before_tiers() {
        let objects = map(TIERED);
        let org = sightings(&[ORG]);
        assert_eq!(
            judge(&refs(&org), &refs(&org), CLOSED, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }

    #[test]
    fn an_administrator_listing_proves_nothing_to_another_session() {
        let objects = map(TIERED);
        let listing = sightings(&[ADMIN]);
        assert_eq!(
            judge(&refs(&listing), &refs(&listing), CLOSED, &objects, false),
            Judged {
                verified: false,
                attempt: None,
            }
        );
    }

    #[test]
    fn an_administrator_listing_proves_the_value_to_an_administrator_session() {
        let objects = map(TIERED);
        let listing = sightings(&[ADMIN]);
        assert_eq!(
            judge(&refs(&listing), &refs(&listing), CLOSED, &objects, true),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }

    #[test]
    fn a_public_sighting_is_an_attempt_for_an_administrator_too() {
        let objects = map(TIERED);
        // The role is not a reason to allow: an administrator who only saw the patient in
        // the public search is judged as anyone else is.
        let search = sightings(&[SEARCH]);
        assert_eq!(
            judge(&refs(&search), &refs(&search), CLOSED, &objects, true),
            Judged {
                verified: false,
                attempt: Some(Attempt::OverPrivilege),
            }
        );
    }

    #[test]
    fn a_value_no_response_showed_is_neither_proven_nor_an_attempt() {
        let objects = map(TIERED);
        assert_eq!(
            judge(&[], &[], CLOSED, &objects, false),
            Judged {
                verified: false,
                attempt: None,
            }
        );
    }

    #[test]
    fn a_site_without_tiers_is_judged_as_before() {
        let objects = map(TIERED);
        let untiered = sightings(&[UNTIERED]);
        assert_eq!(
            judge(&refs(&untiered), &refs(&untiered), CLOSED, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
        assert!(judge(&refs(&untiered), &refs(&untiered), None, &objects, false).verified);
    }

    #[test]
    fn a_public_sighting_without_a_reliability_counts_as_low_and_does_not_tighten() {
        let objects = map(TIERED);
        // An absent reliability is low (docs/07 section 7.9.16): the sighting still proves the
        // value where the position is closed, and it is no attempt.
        let unrated = sightings(&[SEARCH_UNRATED]);
        assert_eq!(
            judge(&refs(&unrated), &refs(&unrated), CLOSED, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }

    #[test]
    fn a_self_sighting_without_a_reliability_proves_the_value_and_is_no_attempt() {
        let objects = map(TIERED);
        // An absent reliability is low, and a self sighting proves whatever its reliability, as a
        // rated one does.
        let own = sightings(&[OWN_UNRATED]);
        assert_eq!(
            judge(&refs(&own), &refs(&own), CLOSED, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
        // Beside a public sighting it keeps the value from being an attempt, as a rated one does.
        let sources = sightings(&[SEARCH, OWN_UNRATED]);
        assert_eq!(
            judge(&refs(&sources), &refs(&sources), CLOSED, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }

    #[test]
    fn a_position_without_a_reliability_is_not_closed_enough_to_tighten() {
        let objects = map(TIERED);
        // The map says the position takes no public source, but without a reliability it is
        // only low on that, so the sure public sighting still proves the value.
        let access = request_access(&objects, "PUT /api/notes/{id} path[2]");
        assert_eq!(
            access,
            Some(PublicAccess {
                accepts: false,
                reliability: Reliability::Low,
            })
        );
        let search = sightings(&[SEARCH]);
        assert_eq!(
            judge(&refs(&search), &refs(&search), access, &objects, false),
            Judged {
                verified: true,
                attempt: None,
            }
        );
    }
}
