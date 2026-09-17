use super::{
    IdentityRuntimeError, MAX_BEARER_BYTES, ProtectedIdentity, RequestResource, denied_reason,
};
use pingora::http::RequestHeader;
use xshield_core::{
    access::ShareTokenFingerprint,
    admission::AdmissionProof,
    audit::ReasonCode,
    identity::UnixSeconds,
    ports::{ShareGrantProofQuery, ShareGrantProofState, ShareGrantProofStore},
};
use xshield_gateway::share_token::fingerprint_share_token;
use xshield_gateway::{GatewayConfig, GatewayDecision};

pub(super) const SHARE_TOKEN_HEADER: &str = "x-xshield-share-token";

impl ProtectedIdentity {
    pub(super) async fn admit_share_entry(
        &self,
        config: &GatewayConfig,
        request: &RequestHeader,
        method: &str,
        path: &str,
        now: UnixSeconds,
    ) -> Result<GatewayDecision, IdentityRuntimeError> {
        let Some(operation) = config.resource_operation(method, path) else {
            return Ok(denied(config, method, path, now));
        };
        let Ok(scope) = RequestResource::parse(
            request.uri.path(),
            request.uri.query(),
            operation.location,
            operation.resource_type,
            &self.fingerprint_key,
            config,
        ) else {
            return Ok(denied(config, method, path, now));
        };
        if scope.fields.len() != 1 {
            return Ok(denied(config, method, path, now));
        }
        let token = match share_token(request, &self.fingerprint_key, config) {
            Ok(token) => token,
            Err(IdentityRuntimeError::Missing | IdentityRuntimeError::Malformed) => {
                return Ok(denied(config, method, path, now));
            }
            Err(error) => return Err(error),
        };
        let state = self
            .store()
            .await?
            .load_share_grant(ShareGrantProofQuery {
                tenant_id: config.tenant_id(),
                site_id: config.site_id(),
                token_fingerprint: &token,
                resource_type: operation.resource_type,
                resource_key: &scope.key,
                operation_id: operation.operation_id,
                view_profile: operation.view_profile,
                now,
            })
            .await?;
        Ok(match state {
            ShareGrantProofState::Verified(grant) => config.admit_scoped_with_proof(
                method,
                path,
                now,
                &scope.target,
                &scope.fields,
                Some(&scope.key),
                AdmissionProof::Share {
                    grant: &grant,
                    token_fingerprint: &token,
                },
            ),
            ShareGrantProofState::Denied(_) => denied(config, method, path, now),
        })
    }
}

fn denied(config: &GatewayConfig, method: &str, path: &str, now: UnixSeconds) -> GatewayDecision {
    denied_reason(config, method, path, now, ReasonCode::ShareScopeMismatch)
}

fn share_token(
    request: &RequestHeader,
    key: &[u8; 32],
    config: &GatewayConfig,
) -> Result<ShareTokenFingerprint, IdentityRuntimeError> {
    let mut values = request.headers.get_all(SHARE_TOKEN_HEADER).iter();
    let value = values.next().ok_or(IdentityRuntimeError::Missing)?;
    if values.next().is_some() {
        return Err(IdentityRuntimeError::Malformed);
    }
    let value = value
        .to_str()
        .map_err(|_| IdentityRuntimeError::Malformed)?;
    if value.is_empty() || value.len() > MAX_BEARER_BYTES {
        return Err(IdentityRuntimeError::Malformed);
    }
    fingerprint_share_token(key, config.tenant_id(), config.site_id(), value)
        .map_err(|_| IdentityRuntimeError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9; 32];

    fn config(site_id: &str) -> GatewayConfig {
        let json = serde_json::json!({
            "listen": "127.0.0.1:6188",
            "origin": {"address": "127.0.0.1:8080", "server_name": "origin.example", "tls": false},
            "tenant_id": "tenant_share",
            "site_id": site_id,
            "policy_revision": "policy-r1",
            "audit": {
                "directory": "target/xshield-share-test",
                "key_id": "journal-key-r1",
                "producer_id": "edge-test",
                "max_bytes": 1_048_576,
                "high_watermark_bytes": 786_432,
                "segment_max_bytes": 262_144
            },
            "identity_store": {"max_connections": 2, "acquire_timeout_ms": 1000},
            "operations": [{
                "operation_id": "records.share.read",
                "method": "GET",
                "path": "/shared-record",
                "admission": "SHARE_ENTRY",
                "source_action": null,
                "resource_type": "record",
                "view_profile": "shared_summary",
                "resource_query_parameter": "record_id"
            }]
        });
        GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()).unwrap()
    }

    #[test]
    fn token_is_single_bounded_and_site_scoped() {
        let mut request = RequestHeader::build("GET", b"/shared-record", Some(1)).unwrap();
        request
            .insert_header(SHARE_TOKEN_HEADER, "share-secret")
            .unwrap();
        let first = share_token(&request, &KEY, &config("site_first")).unwrap();
        let second = share_token(&request, &KEY, &config("site_second")).unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
        request
            .append_header(SHARE_TOKEN_HEADER, "substituted-secret")
            .unwrap();
        assert!(matches!(
            share_token(&request, &KEY, &config("site_first")),
            Err(IdentityRuntimeError::Malformed)
        ));
    }
}
