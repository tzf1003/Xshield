//! Strict, bounded validation of optional Vercel AI Gateway response metadata.
//!
//! Metadata provides routing diagnostics only. Validating provider-reported
//! charges does not establish token usage, settlement, or an exact model revision.
//! The caller owns response byte limits, evidence capture, and terminal audit.

use serde::Deserialize;

use super::RESPONSE_INVALID;

const IDENTIFIER_BYTES_MAX: usize = 256;
const DECIMAL_BYTES_MAX: usize = 64;

/// Optional provider diagnostics accepted after the enclosing response parses.
/// Unknown and repeated fields are rejected by the typed deserializer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderMetadata {
    gateway: Option<GatewayMetadata>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GatewayMetadata {
    routing: Option<GatewayRouting>,
    generation_id: Option<String>,
    cost: Option<String>,
    market_cost: Option<String>,
    surcharge_cost: Option<String>,
    gateway_cost: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GatewayRouting {
    original_model_id: Option<String>,
    resolved_provider: Option<String>,
    canonical_slug: Option<String>,
    final_provider: Option<String>,
    // Retain the routing-level fields accepted by earlier adapter fixtures.
    generation_id: Option<String>,
    cost: Option<f64>,
}

impl ProviderMetadata {
    /// Validates optional diagnostics while preserving their absence semantics.
    ///
    /// # Errors
    /// Returns `MODEL_RESPONSE_INVALID` for invalid identifiers or charges. The
    /// caller records the captured response and terminal validation failure.
    /// This consumes diagnostics without publishing or calculating any cost.
    pub(super) fn validate(self) -> Result<(), &'static str> {
        let Some(gateway) = self.gateway else {
            return Ok(());
        };
        if gateway
            .generation_id
            .as_deref()
            .is_some_and(|value| !valid_identifier(value))
            || [
                gateway.cost,
                gateway.market_cost,
                gateway.surcharge_cost,
                gateway.gateway_cost,
            ]
            .into_iter()
            .flatten()
            .any(|value| !valid_decimal(&value))
        {
            return Err(RESPONSE_INVALID);
        }
        let Some(routing) = gateway.routing else {
            return Ok(());
        };
        if [
            routing.original_model_id,
            routing.resolved_provider,
            routing.canonical_slug,
            routing.final_provider,
            routing.generation_id,
        ]
        .into_iter()
        .flatten()
        .any(|value| !valid_identifier(&value))
            || routing
                .cost
                .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
        {
            return Err(RESPONSE_INVALID);
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= IDENTIFIER_BYTES_MAX
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

// Gateway documents charges as decimal strings. Validate their spelling rather
// than rounding through floating point or inferring a billing total. The local
// 64-byte bound permits precise fractional charges while limiting diagnostics.
fn valid_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > DECIMAL_BYTES_MAX {
        return false;
    }
    let (integer, fraction) = value
        .split_once('.')
        .map_or((value, None), |(integer, fraction)| {
            (integer, Some(fraction))
        });
    !integer.is_empty()
        && integer.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.is_none_or(|fraction| {
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn validate(source: &str) -> Result<(), &'static str> {
        serde_json::from_str::<ProviderMetadata>(source)
            .map_err(|_| RESPONSE_INVALID)?
            .validate()
    }

    fn validate_value(value: &Value) -> Result<(), &'static str> {
        validate(&serde_json::to_string(value).unwrap())
    }

    #[test]
    fn accepts_official_gateway_metadata_sample() {
        // https://vercel.com/docs/ai-gateway/sdks-and-apis/typesafe
        let source = r#"{"gateway":{
            "routing":{"originalModelId":"typesafe-ai/jev",
                "resolvedProvider":"typesafe-ai","canonicalSlug":"typesafe-ai/jev",
                "finalProvider":"typesafe-ai"},
            "cost":"0.00001155","marketCost":"0.00001155",
            "surchargeCost":"0","gatewayCost":"0.00001155",
            "generationId":"gen_..."}}"#;
        assert_eq!(validate(source), Ok(()));
    }

    #[test]
    fn accepts_absent_metadata_and_legacy_routing_diagnostics() {
        for source in [
            "{}",
            r#"{"gateway":null}"#,
            r#"{"gateway":{}}"#,
            r#"{"gateway":{"routing":null,"cost":null,"generationId":null}}"#,
            r#"{"gateway":{"routing":{"generationId":"gen_1","cost":0.0}}}"#,
        ] {
            assert_eq!(validate(source), Ok(()));
        }
    }

    #[test]
    fn charges_accept_only_bounded_unsigned_decimal_strings() {
        for field in ["cost", "marketCost", "surchargeCost", "gatewayCost"] {
            for valid in [
                "0".to_owned(),
                "12.345".to_owned(),
                "9".repeat(DECIMAL_BYTES_MAX),
            ] {
                assert_eq!(validate_value(&json!({"gateway":{field:valid}})), Ok(()));
            }
            for invalid in [
                json!(""),
                json!("-1"),
                json!("+1"),
                json!("1e2"),
                json!("NaN"),
                json!("Infinity"),
                json!(".1"),
                json!("1."),
                json!("1.2.3"),
                json!(" 1"),
                json!("1\n"),
                json!("１"),
                json!("1".repeat(DECIMAL_BYTES_MAX + 1)),
                json!(0),
                json!(0.1),
                json!(false),
                json!([]),
                json!({}),
            ] {
                assert_eq!(
                    validate_value(&json!({"gateway":{field:invalid}})),
                    Err(RESPONSE_INVALID),
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn identifiers_are_bounded_visible_ascii_at_both_supported_locations() {
        for field in [
            "originalModelId",
            "resolvedProvider",
            "canonicalSlug",
            "finalProvider",
            "generationId",
        ] {
            for invalid in [
                String::new(),
                " ".to_owned(),
                "a\nb".to_owned(),
                "模型".to_owned(),
                "x".repeat(IDENTIFIER_BYTES_MAX + 1),
            ] {
                assert_eq!(
                    validate_value(&json!({"gateway":{"routing":{field:invalid}}})),
                    Err(RESPONSE_INVALID)
                );
                if field == "generationId" {
                    assert_eq!(
                        validate_value(&json!({"gateway":{field:invalid}})),
                        Err(RESPONSE_INVALID)
                    );
                }
            }
            assert_eq!(
                validate_value(
                    &json!({"gateway":{"routing":{field:"x".repeat(IDENTIFIER_BYTES_MAX)}}})
                ),
                Ok(())
            );
        }
        assert_eq!(
            validate_value(&json!({"gateway":{"generationId":"x".repeat(IDENTIFIER_BYTES_MAX)}})),
            Ok(())
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_mistyped_fields() {
        for source in [
            r#"{"other":{}}"#,
            r#"{"gateway":{"other":0}}"#,
            r#"{"gateway":{"routing":{"other":0}}}"#,
            r#"{"gateway":null,"gateway":{}}"#,
            r#"{"gateway":{"routing":null,"routing":{}}}"#,
            r#"{"gateway":{"cost":null,"cost":"0"}}"#,
            r#"{"gateway":{"generationId":null,"generationId":"gen_1"}}"#,
            r#"{"gateway":{"routing":{"cost":null,"cost":0}}}"#,
            r#"{"gateway":{"routing":{"originalModelId":null,"originalModelId":"x"}}}"#,
            r#"{"gateway":{"generationId":1}}"#,
            r#"{"gateway":{"routing":{"generationId":1}}}"#,
            r#"{"gateway":{"routing":{"cost":"0"}}}"#,
            r#"{"gateway":{"routing":{"cost":-0.1}}}"#,
            r#"{"gateway":{"routing":{"cost":1e309}}}"#,
        ] {
            assert_eq!(validate(source), Err(RESPONSE_INVALID), "{source}");
        }
    }
}
