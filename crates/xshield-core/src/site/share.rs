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
//! derives it from a deployment-held key. The independently approved
//! `share_issuance_rules` row the edge also requires at issuance time is *not*
//! provisioned by the control plane (see docs/29): without it issuance fails
//! closed.
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
    /// Identifier of the independently provisioned share scope rule.
    pub issuance_rule_id: String,
    /// Share lease, 1–86400 seconds.
    pub ttl_seconds: u64,
    /// Live shares per issuing binding, 1–5000.
    pub max_active_shares: u32,
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
