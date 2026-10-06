//! Names gateway features a rejected site configuration asked for.
//!
//! The typed site configuration refuses every member it does not model, so a
//! body asking for an edge feature the control plane deliberately does not
//! manage (`evidence_capture`, `COMPATIBILITY` request crypto and the
//! `SERVICE_IDENTITY` admission) already fails to parse. That failure is
//! correct but anonymous; this module looks at such a body once more, through
//! a lenient typed view that only knows those features, so the control plane
//! can answer with a stable "unsupported feature" reason instead of a generic
//! parse error. It never takes part in accepting anything.
//!
//! Trust boundary: the body is untrusted operator input that was already
//! refused. Parsing is bounded by the caller's body limit; the module is pure.

use serde::{Deserialize, de::IgnoredAny};

/// A gateway feature the control plane recognizes but deliberately cannot
/// manage yet. Each is refused with `CONTROL_SITE_FEATURE_UNSUPPORTED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedEdgeFeature {
    /// `SERVICE_IDENTITY` admission.
    ServiceIdentityAdmission,
    /// `COMPATIBILITY` request crypto (opaque pass-through with approval).
    CompatibilityRequestCrypto,
    /// `response.evidence_capture`.
    EvidenceCapture,
}

impl UnsupportedEdgeFeature {
    /// Returns the stable lower-case name used in logs and docs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceIdentityAdmission => "service_identity",
            Self::CompatibilityRequestCrypto => "compatibility_request_crypto",
            Self::EvidenceCapture => "evidence_capture",
        }
    }
}

/// Lenient view of a rejected body: only the members that name a gateway
/// feature this model refuses. It never decides acceptance.
#[derive(Deserialize)]
struct BodyProbe {
    #[serde(default)]
    policy: Option<PolicyProbe>,
}

#[derive(Deserialize)]
struct PolicyProbe {
    #[serde(default)]
    routes: Option<Vec<RouteProbe>>,
}

#[derive(Deserialize)]
struct RouteProbe {
    #[serde(default)]
    security_entry: Option<String>,
    #[serde(default)]
    admission: Option<String>,
    #[serde(default)]
    request_crypto: Option<CryptoProbe>,
    #[serde(default)]
    response: Option<ResponseProbe>,
    #[serde(flatten)]
    effects: EffectsProbe,
}

#[derive(Deserialize)]
struct CryptoProbe {
    #[serde(default)]
    mode: Option<String>,
}

#[derive(Deserialize)]
struct ResponseProbe {
    #[serde(flatten)]
    effects: EffectsProbe,
}

/// The response effects the model refuses, whether spelled on the route or
/// inside a gateway-style nested `response` object.
#[derive(Deserialize)]
struct EffectsProbe {
    #[serde(default)]
    evidence_capture: Option<IgnoredAny>,
}

impl EffectsProbe {
    fn feature(&self) -> Option<UnsupportedEdgeFeature> {
        if self.evidence_capture.is_some() {
            Some(UnsupportedEdgeFeature::EvidenceCapture)
        } else {
            None
        }
    }
}

/// Names the first gateway feature a site configuration body asks for that
/// this model deliberately does not manage.
///
/// Only for classifying a body the strict typed parse already refused: the
/// caller reports a specific stable reason instead of a generic parse error,
/// and nothing is ever accepted on the strength of this function. Returns
/// `None` when the body is not JSON of the expected outer shape or names no
/// such feature.
#[must_use]
pub fn find_unsupported_edge_feature(body: &[u8]) -> Option<UnsupportedEdgeFeature> {
    let probe = serde_json::from_slice::<BodyProbe>(body).ok()?;
    probe.policy?.routes?.iter().find_map(|route| {
        let admission = [&route.security_entry, &route.admission]
            .into_iter()
            .flatten()
            .find_map(|value| match value.to_ascii_lowercase().as_str() {
                "service_identity" => Some(UnsupportedEdgeFeature::ServiceIdentityAdmission),
                _ => None,
            });
        admission
            .or_else(|| {
                route
                    .request_crypto
                    .as_ref()
                    .and_then(|crypto| crypto.mode.as_deref())
                    .filter(|mode| mode.eq_ignore_ascii_case("COMPATIBILITY"))
                    .map(|_| UnsupportedEdgeFeature::CompatibilityRequestCrypto)
            })
            .or_else(|| route.effects.feature())
            .or_else(|| route.response.as_ref()?.effects.feature())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::SiteConfig;

    const BROWSER_LOOP: &str = include_str!("../../../../tests/site-config/browser-loop.json");

    #[test]
    fn unsupported_edge_features_are_named_never_accepted() {
        let with_route = |route: &str| {
            format!(
                r#"{{"display_name":"x","policy":{{"routes":[{{"operation_id":"a",{route}}}]}}}}"#
            )
        };
        for (route, feature) in [
            (
                r#""security_entry":"SERVICE_IDENTITY""#,
                UnsupportedEdgeFeature::ServiceIdentityAdmission,
            ),
            (
                r#""request_crypto":{"mode":"COMPATIBILITY","approval_ref":"a"}"#,
                UnsupportedEdgeFeature::CompatibilityRequestCrypto,
            ),
            (
                r#""response":{"evidence_capture":{}}"#,
                UnsupportedEdgeFeature::EvidenceCapture,
            ),
            (
                r#""evidence_capture":{"max_bytes":1}"#,
                UnsupportedEdgeFeature::EvidenceCapture,
            ),
        ] {
            let body = with_route(route);
            assert_eq!(
                find_unsupported_edge_feature(body.as_bytes()),
                Some(feature),
                "{route}"
            );
            assert!(serde_json::from_str::<SiteConfig>(&body).is_err());
        }
        for body in [
            with_route(r#""security_entry":"auth_entry""#),
            with_route(r#""share_issue":null"#),
            with_route(r#""security_entry":"share_entry""#),
            with_route(r#""auth_refresh":{"success_status":200}"#),
            with_route(r#""auth_context_switch":null"#),
            with_route(r#""request_crypto":{"mode":"OBSERVE"}"#),
            r#"{"policy":{"routes":"not routes"}}"#.to_owned(),
            "not json".to_owned(),
            BROWSER_LOOP.to_owned(),
        ] {
            assert_eq!(
                find_unsupported_edge_feature(body.as_bytes()),
                None,
                "{body}"
            );
        }
        assert_eq!(
            UnsupportedEdgeFeature::CompatibilityRequestCrypto.as_str(),
            "compatibility_request_crypto"
        );
    }
}
