use super::{ProtectedIdentity, ResponseIdentity};
use xshield_core::{
    access::ShareIssueAuthority,
    audit::ReasonCode,
    domain::{EventId, IssuanceKey, RequestId},
    identity::UnixSeconds,
};
use xshield_gateway::{
    GatewayConfig, ResponseShareOperation,
    share_issue::{ShareIssueApi, ShareIssueRequest, ShareIssueResponse},
    share_token::ShareToken,
};

impl ProtectedIdentity {
    /// Issues from the admission-selected grant after response shape/size checks.
    /// The immutable configuration selects the rule and limited target; neither
    /// is supplied by the browser or origin. The returned secret exists only
    /// after current authority and the v3 issuance event commit together.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_response_share(
        &self,
        config: &GatewayConfig,
        identity: &ResponseIdentity,
        operation: ResponseShareOperation<'_>,
        request_id: &RequestId,
        trace_id: &str,
        now: UnixSeconds,
    ) -> Result<ShareToken, ReasonCode> {
        let source = identity
            .share_source
            .as_ref()
            .ok_or(ReasonCode::ShareSourceIneligible)?;
        let tokens = self
            .share_tokens
            .as_ref()
            .ok_or(ReasonCode::IdentityStoreUnavailable)?;
        let expires_at = now
            .value()
            .checked_add(operation.rule.ttl_seconds())
            .map(UnixSeconds::new)
            .ok_or(ReasonCode::ShareSourceIneligible)?
            .min(identity.binding.absolute_expires_at())
            .min(source.expires_at);
        if expires_at <= now {
            return Err(ReasonCode::ShareSourceIneligible);
        }
        let authority = ShareIssueAuthority {
            resource_grant_id: source.grant_id.clone(),
            rule_id: operation.rule.issuance_rule_id().clone(),
            operation_id: operation.source_operation_id.clone(),
            view_profile: operation.source_view_profile.clone(),
        };
        // One configured issuance per edge request. These values stay stable
        // within this attempt; a new HTTP request is a separate issuance, not a
        // client-controlled replay of another request's successful response.
        let suffix = request_id
            .as_str()
            .strip_prefix("req_")
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let event_id = EventId::parse(format!("ev_{suffix}"))
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let issuance_key = IssuanceKey::parse(format!("share-response-{suffix}"))
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let store = self
            .store()
            .await
            .map_err(|_| ReasonCode::IdentityStoreUnavailable)?;
        match ShareIssueApi::new(store, tokens)
            .issue(ShareIssueRequest {
                snapshot: &identity.snapshot,
                authority: &authority,
                issuance_key,
                resource_type: operation.resource_type.clone(),
                resource_key: source.resource_key.clone(),
                operation_id: operation.rule.target_operation_id().clone(),
                view_profile: operation.view_profile.clone(),
                policy_revision: config.policy_revision().clone(),
                expires_at,
                event_id: &event_id,
                request_id,
                trace_id,
                now,
                max_active_shares: operation.rule.max_active_shares(),
            })
            .await
            .map_err(|error| error.reason_code())?
        {
            ShareIssueResponse::Granted { token, .. } => Ok(token),
            ShareIssueResponse::Denied { reason_code } => Err(reason_code),
        }
    }
}
