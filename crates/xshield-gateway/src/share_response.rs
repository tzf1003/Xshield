//! Fixed JSON-field delivery of committed, resource-scoped share credentials.

use crate::{
    response_grant::{ResponseGrantError, strict_json},
    share_token::ShareToken,
};
use std::ops::Range;
use xshield_core::{
    audit::ReasonCode,
    domain::{FieldName, OperationId, ShareIssuanceRuleId},
};

const TOKEN_BYTES: usize = 64;

/// Trusted response rule referencing one independently approved share scope.
#[derive(Debug)]
pub struct ResponseShareRule {
    pub(crate) success_status: u16,
    pub(crate) token_field: FieldName,
    pub(crate) target_operation_id: OperationId,
    pub(crate) issuance_rule_id: ShareIssuanceRuleId,
    pub(crate) ttl_seconds: u64,
    pub(crate) max_active_shares: u32,
}

impl ResponseShareRule {
    /// Validates a complete successful JSON object and reserves its token field.
    ///
    /// Other statuses return `None` and issue no share. The selected field must
    /// be absent, including when the origin supplied null. Preparation preserves
    /// the original JSON values and allocates the final bounded body before any
    /// transaction. Only trailing JSON whitespace is discarded.
    ///
    /// # Errors
    /// Returns a stable response-validation, size, or allocation reason. Callers
    /// must record the failure in the request audit and release no credential.
    pub fn prepare(
        &self,
        status: u16,
        body: &[u8],
        max_bytes: usize,
    ) -> Result<Option<PreparedShareResponse>, ReasonCode> {
        if status != self.success_status {
            return Ok(None);
        }
        if body.len() > max_bytes {
            return Err(ReasonCode::ResponseBodyTooLarge);
        }
        let value = strict_json(body).map_err(ResponseGrantError::reason_code)?;
        let object = value
            .as_object()
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        if object.contains_key(self.token_field.as_str()) {
            return Err(ReasonCode::ResponseValidationFailed);
        }
        let comma = usize::from(!object.is_empty());
        drop(value);
        let closing = body
            .iter()
            .rposition(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
            .filter(|index| body[*index] == b'}')
            .ok_or(ReasonCode::ResponseValidationFailed)?;
        let field = serde_json::to_vec(self.token_field.as_str())
            .map_err(|_| ReasonCode::ResponseValidationFailed)?;
        let token_start = closing
            .checked_add(comma)
            .and_then(|length| length.checked_add(field.len()))
            .and_then(|length| length.checked_add(2))
            .ok_or(ReasonCode::ResponseBodyTooLarge)?;
        let token_end = token_start
            .checked_add(TOKEN_BYTES)
            .ok_or(ReasonCode::ResponseBodyTooLarge)?;
        let final_length = token_end
            .checked_add(2)
            .filter(|length| *length <= max_bytes)
            .ok_or(ReasonCode::ResponseBodyTooLarge)?;
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(final_length)
            .map_err(|_| ReasonCode::ResponseBufferCapacityExhausted)?;
        // Copy the validated JSON representation so large integers, exponent
        // spelling, and signed zero keep the origin's exact value semantics.
        prepared.extend_from_slice(&body[..closing]);
        if comma != 0 {
            prepared.push(b',');
        }
        prepared.extend_from_slice(&field);
        prepared.extend_from_slice(b":\"");
        prepared.resize(token_end, b'0');
        prepared.extend_from_slice(b"\"}");
        Ok(Some(PreparedShareResponse {
            body: prepared,
            token_range: token_start..token_end,
        }))
    }

    /// Returns the sole business-success status that can issue a share.
    #[must_use]
    pub const fn success_status(&self) -> u16 {
        self.success_status
    }

    /// Returns the fixed read-only share-entry operation.
    #[must_use]
    pub const fn target_operation_id(&self) -> &OperationId {
        &self.target_operation_id
    }

    /// Returns the independently approved rule revalidated by the transaction.
    #[must_use]
    pub const fn issuance_rule_id(&self) -> &ShareIssuanceRuleId {
        &self.issuance_rule_id
    }

    /// Returns the lease ceiling, further bounded by current source authority.
    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// Returns the transaction-local active-share capacity per issuer binding.
    #[must_use]
    pub const fn max_active_shares(&self) -> u32 {
        self.max_active_shares
    }
}

/// Complete bounded response with a fixed slot for a post-commit credential.
///
/// The body is inaccessible until `finish`; this type intentionally has no
/// formatter so future callers cannot accidentally log the release buffer.
pub struct PreparedShareResponse {
    body: Vec<u8>,
    token_range: Range<usize>,
}

impl PreparedShareResponse {
    /// Inserts a committed share token into the preallocated response body.
    ///
    /// The caller must obtain `token` from a successful `ShareIssueApi` result.
    /// This step performs no allocation or JSON serialization and the credential
    /// never enters a JSON tree. The returned bytes are solely for client release.
    ///
    /// # Errors
    /// Returns a stable validation reason if the credential format or prepared
    /// slot violates the fixed token contract; no partial body is returned.
    pub fn finish(mut self, token: &ShareToken) -> Result<Vec<u8>, ReasonCode> {
        let token = token.expose_secret().as_bytes();
        if token.len() != TOKEN_BYTES
            || !token
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ReasonCode::ResponseValidationFailed);
        }
        self.body
            .get_mut(self.token_range)
            .filter(|slot| slot.len() == TOKEN_BYTES)
            .ok_or(ReasonCode::ResponseValidationFailed)?
            .copy_from_slice(token);
        Ok(self.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share_token::ShareTokenIssuer;
    use xshield_core::domain::{IssuanceKey, SiteId, TenantId};

    fn rule() -> ResponseShareRule {
        ResponseShareRule {
            success_status: 200,
            token_field: FieldName::parse("share_token").unwrap(),
            target_operation_id: OperationId::parse("records.share.read").unwrap(),
            issuance_rule_id: ShareIssuanceRuleId::parse("record-share-r1").unwrap(),
            ttl_seconds: 300,
            max_active_shares: 100,
        }
    }

    fn token() -> ShareToken {
        ShareTokenIssuer::from_hex(&"11".repeat(32), &"22".repeat(32))
            .unwrap()
            .issue(
                &TenantId::parse("tenant_test").unwrap(),
                &SiteId::parse("site_test").unwrap(),
                &IssuanceKey::parse("response-share-test").unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn prepares_bounded_objects_and_preserves_origin_number_representation() {
        let token = token();
        for (body, prefix) in [
            ("{}", "{"),
            ("  { \n } \r\n", "  { \n "),
            (
                "{\"large\":184467440737095516160,\"exponent\":1e+8,\"zero\":-0.0} \n",
                "{\"large\":184467440737095516160,\"exponent\":1e+8,\"zero\":-0.0,",
            ),
        ] {
            let expected = format!("{prefix}\"share_token\":\"{}\"}}", token.expose_secret());
            let prepared = rule()
                .prepare(200, body.as_bytes(), expected.len())
                .unwrap()
                .unwrap();
            let released = prepared.finish(&token).unwrap();
            assert_eq!(released, expected.as_bytes());
            assert_eq!(
                strict_json(&released).unwrap()["share_token"],
                token.expose_secret()
            );
            assert!(matches!(
                rule().prepare(200, body.as_bytes(), expected.len() - 1),
                Err(ReasonCode::ResponseBodyTooLarge)
            ));
        }
    }

    #[test]
    fn rejects_ambiguous_shapes_and_origin_token_fields_before_issuance() {
        for body in [
            "[]",
            "null",
            "{",
            "{} {}",
            "{\"share_token\":null}",
            "{\"share_token\":\"origin\"}",
            "{\"share_token\":1,\"share_token\":2}",
            "{\"nested\":{\"id\":1,\"id\":2}}",
        ] {
            assert!(matches!(
                rule().prepare(200, body.as_bytes(), 1024),
                Err(ReasonCode::ResponseValidationFailed)
            ));
        }
        assert!(rule().prepare(500, b"{}", 1024).unwrap().is_none());
        assert!(matches!(
            rule().prepare(200, b"{}", 1),
            Err(ReasonCode::ResponseBodyTooLarge)
        ));
    }
}
