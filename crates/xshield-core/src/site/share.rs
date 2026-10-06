//! Typed control-plane spelling of response-issued share credentials: the
//! `share_issue` route block and the `share_entry` admission it targets.
//!
//! Mirrors the edge compiler (`xshield-gateway`, `compile_response` for the
//! block's own limits and `validate_response_share_contract` for the
//! source/target contract). A share issuer is a `ui_action_required` GET
//! resource route whose successful JSON response gets one fixed field added,
//! carrying a reusable read-only credential for exactly the one resource the
//! request was already qualified for, redeemable only at the single
//! `share_entry` route named as target.
//!
//! Trust boundary: operator configuration, validated before persistence and
//! again by the edge. The credential itself never appears here; the edge
//! derives it from a deployment-held key. The `share_issuance_rules` row the
//! edge also requires at issuance time is a pure function of this block and
//! the two routes it names ([`issuance_rules`]); the control plane's store
//! writes exactly those rows when a revision becomes eligible to reach the
//! edge (docs/29), so approving the block approves the rows.
//!
//! Pure module: no I/O, no clock.

use super::{SecurityEntry, SiteRouteConfig};
use crate::domain::{FieldName, InvalidValue, OperationId, ShareIssuanceRuleId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// [`InvalidValue`] field for share issuance rules (`share_issue`, and its
/// target's resource binding).
pub const SHARE_ISSUE_INVALID: &str = "site_policy.route.share_issue";

/// Longest lease of an issued share or an active-share budget, as the edge
/// accepts (`compile_response`).
const MAX_SHARE_TTL_SECONDS: u64 = 86_400;
/// Gateway limit on live shares per issuing binding.
const MAX_ACTIVE_SHARES: u32 = 5_000;

/// Share issuance on a `ui_action_required` resource route (edge
/// `response.share_issue`).
///
/// A complete JSON object response with `success_status` gets the field
/// `token_field` appended after the edge committed the share; the field must
/// be absent in the origin's response, a `null` counts as present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteShareIssue {
    /// 2xx status of an issuing response; 204–206 carry no complete body.
    pub success_status: u16,
    /// Member the edge adds to the response object; a scoped name.
    pub token_field: String,
    /// The `share_entry` route that redeems the credential.
    pub target_operation_id: String,
    /// Identifier of the share scope rule; its row (see [`issuance_rules`])
    /// is written by the store when an approval makes the revision eligible.
    pub issuance_rule_id: String,
    /// Share lease, 1–86400 seconds.
    pub ttl_seconds: u64,
    /// Live shares per issuing binding, 1–5000.
    pub max_active_shares: u32,
}

/// One `share_issuance_rules` row an issuer route needs, derived from the
/// typed block and the two routes it binds; never from request-supplied
/// free-form values.
///
/// Field for field what the edge compares at issuance
/// (`PostgresIdentityStore::issue_share_grant`): the rule is looked up by
/// `rule_id` and the label of the revision, and must name the issuer's
/// operation and view, the target's operation and view, and a ceiling not
/// below the lease the edge asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareIssuanceRule {
    /// `share_issue.issuance_rule_id`.
    pub rule_id: String,
    /// The issuer route's operation (`issuer_operation_id` column).
    pub issuer_operation_id: String,
    /// The issuer route's resource view profile.
    pub issuer_view_id: String,
    /// `share_issue.target_operation_id`.
    pub share_operation_id: String,
    /// The `share_entry` target's resource view profile.
    pub share_view_id: String,
    /// `share_issue.ttl_seconds`: the ceiling an issued lease may not exceed.
    pub max_ttl_seconds: u64,
}

/// The rule rows `routes` need, sorted by rule id; empty when no route has a
/// `share_issue`.
///
/// Two issuers may not share a rule id: a rule names exactly one issuer
/// operation, so a shared id could satisfy at most one of them.
///
/// # Errors
/// [`InvalidValue`] named [`SHARE_ISSUE_INVALID`] for a duplicate rule id, a
/// missing target, or an issuer or target without a view profile.
pub fn issuance_rules(routes: &[SiteRouteConfig]) -> Result<Vec<ShareIssuanceRule>, InvalidValue> {
    let invalid = || InvalidValue::new(SHARE_ISSUE_INVALID);
    let mut rules = BTreeMap::new();
    for source in routes {
        let Some(share) = &source.share_issue else {
            continue;
        };
        let target = routes
            .iter()
            .find(|route| route.operation_id == share.target_operation_id)
            .ok_or_else(invalid)?;
        let rule = ShareIssuanceRule {
            rule_id: share.issuance_rule_id.clone(),
            issuer_operation_id: source.operation_id.clone(),
            issuer_view_id: source.view_profile.clone().ok_or_else(invalid)?,
            share_operation_id: share.target_operation_id.clone(),
            share_view_id: target.view_profile.clone().ok_or_else(invalid)?,
            max_ttl_seconds: share.ttl_seconds,
        };
        if rules.insert(rule.rule_id.clone(), rule).is_some() {
            return Err(invalid());
        }
    }
    Ok(rules.into_values().collect())
}

/// Per-route rules of `share_issue`; the generic route and flow rules already
/// ran, so method, path and resource-field shape are valid.
///
/// # Errors
/// [`InvalidValue`] named [`SHARE_ISSUE_INVALID`].
pub(super) fn validate_route(route: &SiteRouteConfig) -> Result<(), InvalidValue> {
    let invalid = || InvalidValue::new(SHARE_ISSUE_INVALID);
    if route.security_entry == SecurityEntry::ShareEntry
        && (route.resource_type.is_none() || route.source_action.is_some() || route.method != "GET")
    {
        // A share entry is exactly one bound resource read (the edge builds
        // its policy with an exact-resource capability).
        return Err(invalid());
    }
    let Some(share) = &route.share_issue else {
        return Ok(());
    };
    // The issuer is the request the caller's action grant and resource grant
    // already qualified: a UI action GET with a resource binding.
    if route.security_entry != SecurityEntry::UiActionRequired
        || route.method != "GET"
        || route.source_action.is_none()
        || route.resource_type.is_none()
        // Share secrets stay in the fixed release buffer; the encryption
        // adapter would copy them into ordinary allocations.
        || route.response_crypto.is_some()
        || !(200..=299).contains(&share.success_status)
        || (204..=206).contains(&share.success_status)
        || FieldName::parse(share.token_field.clone()).is_err()
        || OperationId::parse(share.target_operation_id.clone()).is_err()
        || ShareIssuanceRuleId::parse(share.issuance_rule_id.clone()).is_err()
        || !(1..=MAX_SHARE_TTL_SECONDS).contains(&share.ttl_seconds)
        || !(1..=MAX_ACTIVE_SHARES).contains(&share.max_active_shares)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Cross-route rules of `share_issue`: the target exists, is another
/// `share_entry` GET route over the same resource type, and locates its
/// resource in a query parameter (the issued credential is presented with
/// that one named field, never a path segment).
///
/// # Errors
/// [`InvalidValue`] named [`SHARE_ISSUE_INVALID`].
pub(super) fn validate_route_set(routes: &[SiteRouteConfig]) -> Result<(), InvalidValue> {
    // Each issuer owns its rule id, and the rows the store derives exist.
    issuance_rules(routes)?;
    let by_id = routes
        .iter()
        .map(|route| (route.operation_id.as_str(), route))
        .collect::<BTreeMap<_, _>>();
    for source in routes {
        let Some(share) = &source.share_issue else {
            continue;
        };
        let target = by_id
            .get(share.target_operation_id.as_str())
            .ok_or_else(|| InvalidValue::new(SHARE_ISSUE_INVALID))?;
        if target.security_entry != SecurityEntry::ShareEntry
            || target.method != "GET"
            || target.operation_id == source.operation_id
            || target.resource_type != source.resource_type
            || target.resource_query_parameter.is_none()
        {
            return Err(InvalidValue::new(SHARE_ISSUE_INVALID));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SiteConfig;

    /// The share scope of the loop: one issuer, its `share_entry` target.
    const SHARE_FLOW: &str = include_str!("../../../../tests/site-config/share-flow.json");

    fn share_flow() -> SiteConfig {
        serde_json::from_str(SHARE_FLOW).unwrap()
    }

    fn issuer(config: &mut SiteConfig) -> &mut SiteRouteConfig {
        config
            .policy
            .routes
            .iter_mut()
            .find(|route| route.share_issue.is_some())
            .unwrap()
    }

    #[test]
    fn the_rule_is_what_the_edge_compares_at_issuance() {
        assert_eq!(
            issuance_rules(&share_flow().policy.routes).unwrap(),
            vec![ShareIssuanceRule {
                rule_id: "record-share-r1".to_owned(),
                issuer_operation_id: "records.share.issue".to_owned(),
                issuer_view_id: "share_controls".to_owned(),
                share_operation_id: "records.share.read".to_owned(),
                share_view_id: "shared_summary".to_owned(),
                max_ttl_seconds: 300,
            }]
        );
    }

    #[test]
    fn a_configuration_without_share_issue_needs_no_rule() {
        let mut config = share_flow();
        issuer(&mut config).share_issue = None;
        assert_eq!(issuance_rules(&config.policy.routes).unwrap(), vec![]);
    }

    #[test]
    fn the_rule_follows_the_block_and_the_two_routes_only() {
        let mut config = share_flow();
        issuer(&mut config)
            .share_issue
            .as_mut()
            .unwrap()
            .ttl_seconds = 60;
        issuer(&mut config).view_profile = Some("other_controls".to_owned());
        config
            .policy
            .routes
            .iter_mut()
            .find(|route| route.operation_id == "records.share.read")
            .unwrap()
            .view_profile = Some("other_summary".to_owned());
        let rules = issuance_rules(&config.policy.routes).unwrap();
        assert_eq!(rules[0].max_ttl_seconds, 60);
        assert_eq!(rules[0].issuer_view_id, "other_controls");
        assert_eq!(rules[0].share_view_id, "other_summary");
    }

    #[test]
    fn two_issuers_may_not_share_a_rule_id() {
        let mut config = share_flow();
        let mut second = issuer(&mut config).clone();
        second.operation_id = "records.share.issue.two".to_owned();
        second.path = "/share-issue-two".to_owned();
        config.policy.routes.push(second);
        assert_eq!(
            issuance_rules(&config.policy.routes).unwrap_err().field(),
            SHARE_ISSUE_INVALID
        );
        assert_eq!(
            validate_route_set(&config.policy.routes)
                .unwrap_err()
                .field(),
            SHARE_ISSUE_INVALID
        );
    }

    #[test]
    fn a_missing_target_or_view_yields_no_rule() {
        let mut config = share_flow();
        issuer(&mut config).view_profile = None;
        assert!(issuance_rules(&config.policy.routes).is_err());
        let mut config = share_flow();
        issuer(&mut config)
            .share_issue
            .as_mut()
            .unwrap()
            .target_operation_id = "gone".to_owned();
        assert!(issuance_rules(&config.policy.routes).is_err());
    }
}
