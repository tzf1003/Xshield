//! Positions: where a value sits in a request or in a response, keyed by the
//! route it travels on (the object-map design note, section 1). A position is
//! `METHOD route-template location`, for example `GET /doctor/{id} path[1]` for
//! a request value and `GET /api/appointments [].doc_id` for a response field.
//!
//! The route template replaces numeric and UUID segments with `{id}`, the
//! same normalization the console groups unmatched traffic with. It is the
//! only place a template is made for positions, so a later change to route
//! templates changes every position in one spot.

use xshield_core::context::{IdentityRole, ObjectMap, PublicAccess, Reliability, Tier};
use xshield_core::path_template::{canonical_path, position_template};

use crate::context::Origin;
use crate::values::ResponseValue;

/// The route template of `path`: numeric and UUID segments become `{id}`.
/// A path the normalization does not accept is kept as it is.
/// The route template of `path`: the path in its canonical spelling, with numeric and UUID
/// segments replaced by `{id}`. A path without a canonical spelling is kept as it is.
#[must_use]
pub fn route_template(path: &str) -> String {
    position_template(path)
}

/// The templates a request is looked up by in the site's function table (docs/07 section 7.9.18).
/// The first is [`route_template`]. When the canonical spelling of `path` still carries an escaped
/// slash (`%2F`) or backslash (`%5C`), a second template is the route of that spelling with those
/// escapes read as `/`, when it differs: an origin or a proxy in front of it may decode the slash
/// before it routes, so `/api/admin%2Fexport` reaches `/api/admin/export`.
#[must_use]
pub fn function_templates(path: &str) -> Vec<String> {
    let first = route_template(path);
    let mut templates = vec![first.clone()];
    if let Some(canonical) = canonical_path(path)
        && (canonical.contains("%2F") || canonical.contains("%5C"))
    {
        let decoded = canonical.replace("%2F", "/").replace("%5C", "/");
        let second = route_template(&decoded);
        if second != first {
            templates.push(second);
        }
    }
    templates
}

/// The position of a request value: `GET /doctor/{id} path[1]`.
#[must_use]
pub fn request_slot(method: &str, path: &str, at: &str) -> String {
    format!("{method} {} {at}", route_template(path))
}

/// The position of a response value: `GET /api/appointments [].doc_id`. `None`
/// when the value's path was too long to keep.
#[must_use]
pub fn response_slot(method: &str, path: &str, at: &str) -> Option<String> {
    (!at.is_empty()).then(|| format!("{method} {} {at}", route_template(path)))
}

/// The response position an origin was seen at, when it has one. An origin
/// records its request as `METHOD /path`.
#[must_use]
pub fn origin_slot(origin: &Origin) -> Option<String> {
    let (method, path) = origin.request.split_once(' ')?;
    response_slot(method, path, &origin.at)
}

/// The kind of object the map gives the position an origin was seen at.
#[must_use]
pub fn origin_object<'a>(objects: &'a ObjectMap, origin: &Origin) -> Option<&'a str> {
    objects.class_of(&origin_slot(origin)?)
}

/// The tier the map gives the response position an origin was seen at, with how sure the
/// map is of it (an absent reliability counts as low, docs/07 section 7.9.16). `None` when
/// the map gives no tier there.
#[must_use]
pub fn origin_tier(objects: &ObjectMap, origin: &Origin) -> Option<(Tier, Reliability)> {
    objects.tier_judgement_of(&origin_slot(origin)?)
}

/// What the map says of a request position about public sources, with how sure it is.
/// `None` when the map says nothing about that position.
#[must_use]
pub fn request_access(objects: &ObjectMap, slot: &str) -> Option<PublicAccess> {
    Some(PublicAccess {
        accepts: objects.accepts_public_of(slot)?,
        reliability: objects.reliability_of(slot).unwrap_or(Reliability::Low),
    })
}

/// Where a request value sits on the map: the declared position that governs it, and what that
/// position says of public sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPlace<'a> {
    /// The key of the declared position that governs the value, when one does.
    pub key: Option<&'a str>,
    /// What the map says of that position about public sources, with how sure it is.
    pub access: Option<PublicAccess>,
}

impl RequestPlace<'_> {
    /// The position the value is shown at: the declared key that governs it, else the position
    /// its path names, as [`request_slot`] gives it.
    #[must_use]
    pub fn slot(&self, method: &str, path: &str, at: &str) -> String {
        self.key
            .map_or_else(|| request_slot(method, path, at), str::to_owned)
    }
}

/// Where a request value of `method` on `path`, at `at`, sits on the map. On a site that judges
/// public access, a declared position whose route covers the path governs the value even where
/// the path spells the segment differently: a slug id, a `;` parameter or an escaped slash (see
/// [`ObjectMap::request_key`]).
#[must_use]
pub fn request_place<'a>(
    objects: &'a ObjectMap,
    method: &str,
    path: &str,
    at: &str,
) -> RequestPlace<'a> {
    let key = objects.request_key(method, &route_template(path), at);
    RequestPlace {
        key,
        access: key.and_then(|key| request_access(objects, key)),
    }
}

/// The name of a tier as the state and the trace write it (docs/07 section 7.9.16).
#[must_use]
pub fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::Own => "self",
        Tier::Org => "org",
        Tier::Admin => "admin",
        Tier::Public => "public",
    }
}

/// The name of a reliability as the state and the trace write it.
#[must_use]
pub fn reliability_name(reliability: Reliability) -> &'static str {
    match reliability {
        Reliability::Low => "low",
        Reliability::Medium => "medium",
        Reliability::High => "high",
    }
}

/// The values a response holds at the positions the map gives an identity (docs/01 section
/// 1.2), each with that identity. `request` is `METHOD /path` as the origins name it, so only
/// the positions of the route the response answered count, and a paused entry states nothing.
#[must_use]
pub fn identity_claims<'a>(
    objects: &ObjectMap,
    request: &str,
    values: &'a [ResponseValue],
) -> Vec<(IdentityRole, &'a str)> {
    let Some((method, path)) = request.split_once(' ') else {
        return Vec::new();
    };
    let route = format!("{method} {}", route_template(path));
    let mut claims = Vec::new();
    for slot in objects.slots() {
        let Some(at) = slot
            .key
            .strip_prefix(route.as_str())
            .and_then(|rest| rest.strip_prefix(' '))
        else {
            continue;
        };
        let Some(kind) = objects.identity_of(&slot.key) else {
            continue;
        };
        claims.extend(
            values
                .iter()
                .filter(|value| value.at == at)
                .map(|value| (kind, value.value.as_str())),
        );
    }
    claims
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_request_is_looked_up_by_its_template_and_by_its_decoded_slash() {
        let cases: [(&str, &[&str]); 6] = [
            ("/api/patients/8", &["/api/patients/{id}"]),
            ("/api/admin/export", &["/api/admin/export"]),
            (
                "/api/admin%2Fexport",
                &["/api/admin%2Fexport", "/api/admin/export"],
            ),
            (
                "/api/admin%2fexport",
                &["/api/admin%2Fexport", "/api/admin/export"],
            ),
            (
                "/api/admin%5Cexport",
                &["/api/admin%5Cexport", "/api/admin/export"],
            ),
            (
                "/api/x/..%2Fadmin/export",
                &["/api/x/..%2Fadmin/export", "/api/admin/export"],
            ),
        ];
        for (path, expected) in cases {
            assert_eq!(function_templates(path), expected, "{path}");
        }
        // A path without a canonical spelling has one template, as it is.
        assert_eq!(function_templates("/api/%zz"), ["/api/%zz"]);
    }

    use super::*;

    #[test]
    fn numeric_and_uuid_segments_become_the_template() {
        assert_eq!(route_template("/doctor/2"), "/doctor/{id}");
        assert_eq!(
            route_template("/api/doctors/7/files/9"),
            "/api/doctors/{id}/files/{id}"
        );
        assert_eq!(route_template("/api/doctors"), "/api/doctors");
    }

    #[test]
    fn equivalent_spellings_of_a_path_name_one_position() {
        assert_eq!(
            request_slot("DELETE", "/api/patients/7005/", "path[2]"),
            "DELETE /api/patients/{id} path[2]"
        );
        assert_eq!(
            request_slot("DELETE", "/api/patients/%37005", "path[2]"),
            "DELETE /api/patients/{id} path[2]"
        );
        assert_eq!(
            response_slot("GET", "/api/search/", "results[].id").as_deref(),
            Some("GET /api/search results[].id")
        );
    }

    #[test]
    fn request_and_response_positions_name_the_route_and_the_location() {
        assert_eq!(
            request_slot("GET", "/doctor/2", "path[1]"),
            "GET /doctor/{id} path[1]"
        );
        assert_eq!(
            response_slot("GET", "/api/appointments", "[].doc_id").as_deref(),
            Some("GET /api/appointments [].doc_id")
        );
        assert_eq!(response_slot("GET", "/api/x", ""), None);
    }

    #[test]
    fn a_response_states_an_identity_only_at_the_positions_the_map_gives_one() {
        let objects: ObjectMap = serde_json::from_str(
            r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
                {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"},
                {"key":"GET /api/home doctor.name","class":"doctor","source":"admin"}]}"#,
        )
        .unwrap();
        let values = vec![
            ResponseValue {
                field: "id".to_owned(),
                value: "DR-A".to_owned(),
                at: "doctor.id".to_owned(),
            },
            ResponseValue {
                field: "name".to_owned(),
                value: "A".to_owned(),
                at: "doctor.name".to_owned(),
            },
        ];
        assert_eq!(
            identity_claims(&objects, "GET /api/home", &values),
            vec![(IdentityRole::User, "DR-A")]
        );
        // Another route, or another method, states nothing.
        assert!(identity_claims(&objects, "GET /api/patients", &values).is_empty());
        assert!(identity_claims(&objects, "POST /api/home", &values).is_empty());
    }

    #[test]
    fn a_declared_id_places_a_slug_a_parameter_and_an_escaped_slash() {
        let objects: ObjectMap = serde_json::from_str(
            r#"{"classes":[{"id":"patient","name":"患者"}],"slots":[
                {"key":"DELETE /api/patients/{id} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"}]}"#,
        )
        .unwrap();
        let closed = Some(PublicAccess {
            accepts: false,
            reliability: Reliability::High,
        });
        for path in [
            "/api/patients/7005/",
            "/api/patients/PT-7004",
            "/api/patients/7005;jsessionid=a",
            "/api/patients/PT%2F7004",
        ] {
            let place = request_place(&objects, "DELETE", path, "path[2]");
            assert_eq!(
                place.key,
                Some("DELETE /api/patients/{id} path[2]"),
                "{path}"
            );
            assert_eq!(place.access, closed, "{path}");
        }
        // Another method, location or number of segments is not the declared position.
        assert_eq!(
            request_place(&objects, "GET", "/api/patients/PT-7004", "path[2]").key,
            None
        );
        assert_eq!(
            request_place(&objects, "DELETE", "/api/patients/PT-7004", "path[1]").key,
            None
        );
        assert_eq!(
            request_place(&objects, "DELETE", "/api/patients/PT-7004/notes", "path[2]").key,
            None
        );
    }

    #[test]
    fn a_position_that_names_the_spelling_wins_over_a_covering_one() {
        let objects: ObjectMap = serde_json::from_str(
            r#"{"classes":[{"id":"patient","name":"患者"}],"slots":[
                {"key":"DELETE /api/patients/{id} path[2]","class":"patient","source":"admin","accepts_public":false,"reliability":"high"},
                {"key":"DELETE /api/patients/PT-7004 path[2]","class":"patient","source":"admin","accepts_public":true,"reliability":"high"}]}"#,
        )
        .unwrap();
        let place = request_place(&objects, "DELETE", "/api/patients/PT-7004", "path[2]");
        assert_eq!(place.key, Some("DELETE /api/patients/PT-7004 path[2]"));
        assert_eq!(
            place.access,
            Some(PublicAccess {
                accepts: true,
                reliability: Reliability::High,
            })
        );
        // Another id still takes the covering position.
        assert_eq!(
            request_place(&objects, "DELETE", "/api/patients/7005", "path[2]").key,
            Some("DELETE /api/patients/{id} path[2]")
        );
    }

    #[test]
    fn an_origin_yields_the_position_it_was_seen_at() {
        let origin = Origin {
            field: "doc_id".to_owned(),
            at: "attachments[].doc_id".to_owned(),
            request: "GET /api/records/7".to_owned(),
            request_id: 0,
            at_ms: 0,
        };
        assert_eq!(
            origin_slot(&origin).as_deref(),
            Some("GET /api/records/{id} attachments[].doc_id")
        );
    }
}
