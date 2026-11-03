//! Positions: where a value sits in a request or in a response, keyed by the
//! route it travels on (the object-map design note, section 1). A position is
//! `METHOD route-template location`, for example `GET /doctor/{id} path[1]` for
//! a request value and `GET /api/appointments [].doc_id` for a response field.
//!
//! The route template replaces numeric and UUID segments with `{id}`, the
//! same normalization the console groups unmatched traffic with. It is the
//! only place a template is made for positions, so a later change to route
//! templates changes every position in one spot.

use xshield_core::context::{IdentityRole, ObjectMap};
use xshield_core::path_template::normalize;

use crate::context::Origin;
use crate::values::ResponseValue;

/// The route template of `path`: numeric and UUID segments become `{id}`.
/// A path the normalization does not accept is kept as it is.
#[must_use]
pub fn route_template(path: &str) -> String {
    normalize(path).unwrap_or_else(|| path.to_owned())
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
