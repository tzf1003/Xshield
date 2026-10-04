//! Strict, bounded validation of optional Vercel AI Gateway response metadata.
//!
//! Metadata provides routing diagnostics only. Validating provider-reported
//! charges does not establish token usage, settlement, or an exact model revision.
//! The caller owns response byte limits, evidence capture, and terminal audit.

use serde::Deserialize;
use std::collections::BTreeMap;

use super::RESPONSE_INVALID;

const IDENTIFIER_BYTES_MAX: usize = 256;
const DECIMAL_BYTES_MAX: usize = 64;

/// Optional provider diagnostics accepted after the enclosing response parses.
/// Unknown and repeated fields are rejected by the typed deserializer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderMetadata {
    typesafe: Option<TypeSafeMetadata>,
    gateway: Option<GatewayMetadata>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TypeSafeMetadata {
    confidence: Option<BTreeMap<String, f64>>,
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
    inference_cost: Option<String>,
    input_inference_cost: Option<String>,
    output_inference_cost: Option<String>,
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
    fallbacks_available: Option<Vec<String>>,
    planning_reasoning: Option<String>,
    model_attempt_count: Option<u32>,
    model_attempts: Option<Vec<ModelAttempt>>,
    total_provider_attempt_count: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ModelAttempt {
    canonical_slug: String,
    #[allow(dead_code)]
    success: bool,
    provider_attempt_count: u32,
    provider_attempts: Vec<ProviderAttempt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProviderAttempt {
    provider: String,
    credential_type: String,
    #[allow(dead_code)]
    success: bool,
    start_time: u64,
    end_time: u64,
    status_code: u16,
}

impl ProviderMetadata {
    /// Validates optional diagnostics while preserving their absence semantics.
    ///
    /// # Errors
    /// Returns `MODEL_RESPONSE_INVALID` for invalid identifiers or charges. The
    /// caller records the captured response and terminal validation failure.
    /// This consumes diagnostics without publishing or calculating any cost.
    pub(super) fn validate(self) -> Result<(), &'static str> {
        if let Some(typesafe) = self.typesafe
            && typesafe.confidence.is_some_and(|values| {
                values.len() > 64
                    || values.iter().any(|(key, value)| {
                        !valid_identifier(key) || !value.is_finite() || !(0.0..=1.0).contains(value)
                    })
            })
        {
            return Err(RESPONSE_INVALID);
        }
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
                gateway.inference_cost,
                gateway.input_inference_cost,
                gateway.output_inference_cost,
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
        if routing.fallbacks_available.as_ref().is_some_and(|values| {
            values.len() > 16 || values.iter().any(|value| !valid_identifier(value))
        }) || routing
            .planning_reasoning
            .as_deref()
            .is_some_and(|value| value.len() > 4096)
            || routing.model_attempts.as_ref().is_some_and(|attempts| {
                attempts.len() > 16
                    || attempts.iter().any(|attempt| {
                        !valid_identifier(&attempt.canonical_slug)
                            || attempt.provider_attempt_count as usize
                                != attempt.provider_attempts.len()
                            || attempt.provider_attempts.len() > 16
                            || attempt.provider_attempts.iter().any(|provider| {
                                !valid_identifier(&provider.provider)
                                    || !valid_identifier(&provider.credential_type)
                                    || provider.end_time < provider.start_time
                                    || !(100..=599).contains(&provider.status_code)
                            })
                    })
            })
            || routing.model_attempt_count.is_some_and(|count| {
                routing
                    .model_attempts
                    .as_ref()
                    .is_some_and(|attempts| usize::try_from(count).ok() != Some(attempts.len()))
            })
            || routing.total_provider_attempt_count.is_some_and(|count| {
                routing.model_attempts.as_ref().is_some_and(|attempts| {
                    let total = attempts
                        .iter()
                        .map(|attempt| attempt.provider_attempts.len())
                        .sum::<usize>();
                    usize::try_from(count).ok() != Some(total)
                })
            })
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
