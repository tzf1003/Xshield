//! Bounded, typed Jev wire conversion for approved offline evaluations.
//!
//! Operator configuration and untrusted text remain separate. This module only
//! validates and serializes; the caller owns transport, evidence, and audit.

use std::{collections::BTreeMap, fmt, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, de};
use xshield_core::domain::{ArtifactId, ModelCallId, RequestId};

use super::transport::{DIRECT_MODEL, GATEWAY_MODEL};

mod gateway_metadata;
use gateway_metadata::ProviderMetadata;
mod risk_mapping;
#[cfg(test)]
mod score_tests;
use risk_mapping::MappingDto;
pub(super) use risk_mapping::RiskProjection;

const INPUT_INVALID: &str = "MODEL_INPUT_INVALID";
const RESPONSE_INVALID: &str = "MODEL_RESPONSE_INVALID";
const MODEL_REVISION: &str = "jev-1.13.0";
const INPUT_BYTES_MAX: usize = 8_192;
const RESPONSE_BYTES_MAX: usize = 65_536;
const TEXT_CHARS_MAX: usize = 6_144;
const OPTIONS_MAX: usize = 32;
const SCORE_LEVELS_MAX: usize = 10;
// Provider decimal serialization may round each probability and the mean.
const SCORE_MEAN_TOLERANCE: f64 = 1e-5;

/// Validated operator input with a pinned model and bounded text.
///
/// Text is exposed only through explicit evidence/API serialization, never
/// through diagnostic formatting. Construction does not authorize execution.
pub(super) struct Input(InputDto);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputDto {
    schema_version: u8,
    approval_ref: String,
    model_revision: String,
    policy_revision: String,
    prompt_revision: String,
    untrusted_content: String,
    question: Question,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    risk_mapping: Option<MappingDto>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Question {
    Choice {
        instructions: String,
        #[serde(deserialize_with = "unique_options")]
        criteria: BTreeMap<String, String>,
    },
    Score {
        instructions: String,
        criteria: Vec<String>,
    },
    Noul {
        instructions: String,
    },
}

impl Input {
    /// Parses one strict, bounded evaluation configuration.
    ///
    /// # Errors
    /// Returns `MODEL_INPUT_INVALID` for malformed, ambiguous, unsupported, or
    /// oversized input. The caller records that reason with its audit context.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > INPUT_BYTES_MAX {
            return Err(INPUT_INVALID);
        }
        let dto: InputDto = serde_json::from_slice(bytes).map_err(|_| INPUT_INVALID)?;
        if dto.schema_version != 1
            || dto.model_revision != MODEL_REVISION
            || [
                &dto.approval_ref,
                &dto.policy_revision,
                &dto.prompt_revision,
            ]
            .into_iter()
            .any(|value| !crate::valid_name(value))
        {
            return Err(INPUT_INVALID);
        }
        let (instructions, criteria_chars) = match &dto.question {
            Question::Choice {
                instructions,
                criteria,
            } => {
                if !(2..=OPTIONS_MAX).contains(&criteria.len())
                    || !criteria.contains_key("NONE")
                    || !criteria.contains_key("UNKNOWN")
                    || criteria
                        .values()
                        .any(|description| !valid_text(description, 512))
                {
                    return Err(INPUT_INVALID);
                }
                let chars = criteria
                    .iter()
                    .map(|(key, description)| key.chars().count() + description.chars().count())
                    .sum::<usize>();
                (instructions, chars)
            }
            Question::Score {
                instructions,
                criteria,
            } => {
                if !(2..=SCORE_LEVELS_MAX).contains(&criteria.len())
                    || criteria
                        .iter()
                        .any(|description| !valid_text(description, 512))
                {
                    return Err(INPUT_INVALID);
                }
                (
                    instructions,
                    criteria.iter().map(|value| value.chars().count()).sum(),
                )
            }
            Question::Noul { instructions } => (instructions, 0),
        };
        let text_chars = [
            &dto.approval_ref,
            &dto.model_revision,
            &dto.policy_revision,
            &dto.prompt_revision,
            &dto.untrusted_content,
            instructions,
        ]
        .into_iter()
        .map(|value| value.chars().count())
        .sum::<usize>()
            + criteria_chars
            + dto.risk_mapping.as_ref().map_or(0, MappingDto::text_chars);
        if !valid_text(instructions, 1_024) || text_chars > TEXT_CHARS_MAX {
            return Err(INPUT_INVALID);
        }
        if let Some(mapping) = &dto.risk_mapping {
            mapping.validate(&dto.question)?;
        }
        Ok(Self(dto))
    }

    /// Serializes the validated internal input for the caller's evidence vault.
    ///
    /// # Errors
    /// Returns `MODEL_INPUT_INVALID` if serialization exceeds the byte budget.
    /// These bytes contain evaluation text and belong in restricted evidence.
    pub(super) fn internal_bytes(&self) -> Result<Vec<u8>, &'static str> {
        bounded_input_bytes(&self.0)
    }

    /// Produces the exact logical provider body with validated evidence links.
    ///
    /// # Errors
    /// Returns `MODEL_INPUT_INVALID` for invalid trace IDs or a body over 8 KiB.
    /// The caller durably captures these bytes before sending them to Jev.
    #[cfg(test)]
    pub(super) fn api_bytes(
        &self,
        request_id: &str,
        model_call_id: &str,
        internal_artifact_id: &str,
    ) -> Result<Vec<u8>, &'static str> {
        self.api_bytes_for_model(
            request_id,
            model_call_id,
            internal_artifact_id,
            DIRECT_MODEL,
        )
    }

    /// Produces the exact provider body for one compile-time approved model id.
    /// The slash-bearing Gateway slug is kept on the wire only; internal model
    /// revision and audit names remain the pinned `jev-1.13.0` revision.
    pub(super) fn api_bytes_for_model(
        &self,
        request_id: &str,
        model_call_id: &str,
        internal_artifact_id: &str,
        provider_model: &str,
    ) -> Result<Vec<u8>, &'static str> {
        if !matches!(provider_model, DIRECT_MODEL | GATEWAY_MODEL) {
            return Err(INPUT_INVALID);
        }
        RequestId::parse(request_id).map_err(|_| INPUT_INVALID)?;
        ModelCallId::parse(model_call_id).map_err(|_| INPUT_INVALID)?;
        ArtifactId::parse(internal_artifact_id).map_err(|_| INPUT_INVALID)?;
        bounded_input_bytes(&ApiRequest {
            model: provider_model,
            state: State {
                trusted_policy: TrustedPolicy {
                    schema_version: 1,
                    scope: "operator_approved_offline_evaluation",
                    approval_ref: &self.0.approval_ref,
                    policy_revision: self.policy_revision(),
                    prompt_revision: self.prompt_revision(),
                },
                auth_facts: Unavailable::OFFLINE,
                page_evidence: Unavailable::OFFLINE,
                untrusted_content: &self.0.untrusted_content,
                coverage: Coverage {
                    untrusted_content: "complete",
                    auth_facts: "unavailable",
                    page_evidence: "unavailable",
                },
                trace_context: TraceContext {
                    request_id,
                    model_call_id,
                    input_artifact_id: internal_artifact_id,
                },
            },
            questions: Questions {
                evaluation: &self.0.question,
            },
        })
    }

    /// Returns the exact requested provider model version for audit metadata.
    #[must_use]
    pub(super) fn model_revision(&self) -> &str {
        &self.0.model_revision
    }

    /// Returns the approved prompt revision for audit metadata.
    #[must_use]
    pub(super) fn prompt_revision(&self) -> &str {
        &self.0.prompt_revision
    }

    /// Returns the approved policy revision for audit metadata.
    #[must_use]
    pub(super) fn policy_revision(&self) -> &str {
        &self.0.policy_revision
    }

    /// Returns the single primitive selected by the validated configuration.
    #[must_use]
    pub(super) fn question_type(&self) -> &'static str {
        match &self.0.question {
            Question::Choice { .. } => "choice",
            Question::Score { .. } => "score",
            Question::Noul { .. } => "noul",
        }
    }
}

fn valid_text(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= max_chars
}

fn bounded_input_bytes(value: &impl Serialize) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| INPUT_INVALID)?;
    if bytes.len() > INPUT_BYTES_MAX {
        return Err(INPUT_INVALID);
    }
    Ok(bytes)
}

#[derive(Serialize)]
struct ApiRequest<'a> {
    model: &'a str,
    state: State<'a>,
    questions: Questions<'a>,
}

#[derive(Serialize)]
struct State<'a> {
    trusted_policy: TrustedPolicy<'a>,
    auth_facts: Unavailable,
    page_evidence: Unavailable,
    untrusted_content: &'a str,
    coverage: Coverage,
    trace_context: TraceContext<'a>,
}

#[derive(Serialize)]
struct TrustedPolicy<'a> {
    schema_version: u8,
    scope: &'static str,
    approval_ref: &'a str,
    policy_revision: &'a str,
    prompt_revision: &'a str,
}

#[derive(Serialize)]
struct Unavailable {
    status: &'static str,
    reason_code: &'static str,
}

impl Unavailable {
    const OFFLINE: Self = Self {
        status: "unavailable",
        reason_code: "OFFLINE_EVALUATION",
    };
}

#[derive(Serialize)]
struct Coverage {
    untrusted_content: &'static str,
    auth_facts: &'static str,
    page_evidence: &'static str,
}

#[derive(Serialize)]
#[allow(clippy::struct_field_names)] // Keep the documented trace-context wire keys.
struct TraceContext<'a> {
    request_id: &'a str,
    model_call_id: &'a str,
    input_artifact_id: &'a str,
}

#[derive(Serialize)]
struct Questions<'a> {
    evaluation: &'a Question,
}

/// Validated provider signal; every field retains provider or absence semantics.
#[derive(Serialize)]
pub(super) struct Response {
    /// Provider model version, verified against the requested pinned revision.
    pub(super) model_revision: String,
    /// Choice identifier, Score expected level, or Noul yes-probability.
    pub(super) result: ResultValue,
    /// Complete Choice/Score distribution; empty for Noul.
    pub(super) probabilities: BTreeMap<String, f64>,
    /// Exact approved zero-based Score labels; other primitives have no legend.
    pub(super) legend: Option<BTreeMap<String, String>>,
    /// Approved binary-risk mapping, when explicitly configured on the input.
    pub(super) risk_projection: Option<RiskProjection>,
    /// Provider confidence as reported; Noul and missing values remain null.
    pub(super) provider_confidence: Option<f64>,
    /// `provided`, `not_provided`, or `not_applicable`.
    pub(super) confidence_status: &'static str,
    /// Provider-reported input tokens, if available.
    pub(super) input_tokens: Option<u64>,
    /// Provider-reported output tokens, if available.
    pub(super) output_tokens: Option<u64>,
    /// `provider` when a count was reported, otherwise `unavailable`.
    pub(super) usage_source: &'static str,
    pub(super) resolved_model_revision: Option<String>,
}

/// Serializes a primitive result using its provider-native scalar type.
#[derive(Clone, Serialize)]
#[serde(untagged)]
pub(super) enum ResultValue {
    /// The highest-probability approved candidate.
    Choice(String),
    /// Expected zero-based level on the approved ordered scale.
    Score(f64),
    /// Provider yes-probability, bounded to the inclusive unit interval.
    Noul(f64),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseDto {
    model: String,
    answers: Answers,
    usage: Option<Usage>,
    #[serde(default)]
    provider_metadata: Option<ProviderMetadata>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answers {
    evaluation: Answer,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Answer {
    Choice {
        choice: String,
        #[serde(deserialize_with = "unique_options")]
        probabilities: BTreeMap<String, f64>,
        confidence: Option<f64>,
    },
    Score {
        score: f64,
        #[serde(deserialize_with = "unique_options")]
        legend: BTreeMap<String, String>,
        #[serde(deserialize_with = "unique_options")]
        probabilities: BTreeMap<String, f64>,
        confidence: Option<f64>,
    },
    Noul {
        noul: f64,
    },
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Usage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}

impl Response {
    /// Validates one bounded provider response against the submitted question.
    ///
    /// # Errors
    /// Returns `MODEL_RESPONSE_INVALID` for schema, model, primitive, candidate,
    /// probability, or usage errors. The caller records the response evidence
    /// and terminal audit state; this conversion performs no external effects.
    #[cfg(test)]
    pub(super) fn parse(bytes: &[u8], input: &Input) -> Result<Self, &'static str> {
        Self::parse_for_model(bytes, input, DIRECT_MODEL)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn parse_for_model(
        bytes: &[u8],
        input: &Input,
        provider_model: &str,
    ) -> Result<Self, &'static str> {
        if bytes.len() > RESPONSE_BYTES_MAX {
            return Err(RESPONSE_INVALID);
        }
        if !matches!(provider_model, DIRECT_MODEL | GATEWAY_MODEL) {
            return Err(RESPONSE_INVALID);
        }
        let dto: ResponseDto = serde_json::from_slice(bytes).map_err(|_| RESPONSE_INVALID)?;
        if dto.model != provider_model {
            return Err(RESPONSE_INVALID);
        }
        if provider_model == DIRECT_MODEL && dto.provider_metadata.is_some() {
            return Err(RESPONSE_INVALID);
        }
        if let Some(metadata) = dto.provider_metadata {
            metadata.validate()?;
        }
        let (result, probabilities, provider_confidence, confidence_status, legend) =
            match (dto.answers.evaluation, &input.0.question) {
                (
                    Answer::Choice {
                        choice,
                        probabilities,
                        confidence,
                    },
                    Question::Choice { criteria, .. },
                ) => {
                    let selected = probabilities.get(&choice).ok_or(RESPONSE_INVALID)?;
                    if !probabilities.keys().eq(criteria.keys())
                        || probabilities
                            .values()
                            .any(|value| !unit_interval(*value) || value > selected)
                        || (probabilities.values().sum::<f64>() - 1.0).abs() > 1e-6
                        || confidence.is_some_and(|value| !unit_interval(value))
                    {
                        return Err(RESPONSE_INVALID);
                    }
                    let status = if confidence.is_some() {
                        "provided"
                    } else {
                        "not_provided"
                    };
                    (
                        ResultValue::Choice(choice),
                        probabilities,
                        confidence,
                        status,
                        None,
                    )
                }
                (
                    Answer::Score {
                        score,
                        legend,
                        probabilities,
                        confidence,
                    },
                    Question::Score { criteria, .. },
                ) => {
                    validate_score(score, &legend, &probabilities, confidence, criteria)?;
                    (
                        ResultValue::Score(score),
                        probabilities,
                        confidence,
                        if confidence.is_some() {
                            "provided"
                        } else {
                            "not_provided"
                        },
                        Some(legend),
                    )
                }
                (Answer::Noul { noul }, Question::Noul { .. }) if unit_interval(noul) => (
                    ResultValue::Noul(noul),
                    BTreeMap::new(),
                    None,
                    "not_applicable",
                    None,
                ),
                _ => return Err(RESPONSE_INVALID),
            };
        let risk_projection = input
            .0
            .risk_mapping
            .as_ref()
            .map(|mapping| mapping.project(&probabilities))
            .transpose()?;
        let usage = dto.usage.unwrap_or_default();
        let usage_source = if usage.input_tokens.is_some() || usage.output_tokens.is_some() {
            "provider"
        } else {
            "unavailable"
        };
        Ok(Self {
            model_revision: input.model_revision().to_owned(),
            resolved_model_revision: (provider_model == DIRECT_MODEL).then_some(dto.model),
            result,
            probabilities,
            legend,
            risk_projection,
            provider_confidence,
            confidence_status,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            usage_source,
        })
    }
}

// The scale is operator-approved; a provider cannot relabel levels or supply a
// most-likely class in place of the documented probability-weighted mean.
fn validate_score(
    score: f64,
    legend: &BTreeMap<String, String>,
    probabilities: &BTreeMap<String, f64>,
    confidence: Option<f64>,
    criteria: &[String],
) -> Result<(), &'static str> {
    let levels = u32::try_from(criteria.len()).map_err(|_| RESPONSE_INVALID)?;
    if !(2..=10).contains(&levels)
        || !score.is_finite()
        || !(0.0..=f64::from(levels - 1)).contains(&score)
        || legend.len() != criteria.len()
        || probabilities.len() != criteria.len()
        || confidence.is_some_and(|value| !unit_interval(value))
    {
        return Err(RESPONSE_INVALID);
    }
    let mut mean = 0.0;
    let mut sum = 0.0;
    for (index, description) in criteria.iter().enumerate() {
        let key = index.to_string();
        let probability = probabilities.get(&key).ok_or(RESPONSE_INVALID)?;
        if legend.get(&key) != Some(description) || !unit_interval(*probability) {
            return Err(RESPONSE_INVALID);
        }
        mean += f64::from(u32::try_from(index).map_err(|_| RESPONSE_INVALID)?) * probability;
        sum += probability;
    }
    if (sum - 1.0).abs() > 1e-6 || (score - mean).abs() > SCORE_MEAN_TOLERANCE {
        return Err(RESPONSE_INVALID);
    }
    Ok(())
}

fn unit_interval(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

// BTreeMap's default deserializer overwrites repeated keys. Both wire maps
// must preserve the one-to-one candidate contract before validation can run.
fn unique_options<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct OptionsVisitor<V>(PhantomData<V>);

    impl<'de, V: Deserialize<'de>> de::Visitor<'de> for OptionsVisitor<V> {
        type Value = BTreeMap<String, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of unique candidate identifiers")
        }

        fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if values.len() >= OPTIONS_MAX
                    || !crate::valid_name(&key)
                    || values.contains_key(&key)
                {
                    return Err(de::Error::custom("invalid candidate map"));
                }
                values.insert(key, map.next_value()?);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(OptionsVisitor(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const REQUEST_ID: &str = "req_01a0afa6-3320-7791-8f45-b4d5a34ffb57";
    const MODEL_CALL_ID: &str = "mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb58";
    const ARTIFACT_ID: &str = "artifact_01a0afa6-3320-7791-8f45-b4d5a34ffb59";
    const CHOICE_INPUT: &str = r#"{"schema_version":1,"approval_ref":"approval-r1","model_revision":"jev-1.13.0","policy_revision":"policy-r1","prompt_revision":"prompt-r1","untrusted_content":"A synthetic evaluation sample.","question":{"type":"choice","instructions":"Choose the matching candidate.","criteria":{"NONE":"No matching candidate.","UNKNOWN":"Insufficient evidence."}}}"#;
    const CHOICE_RESPONSE: &str = r#"{"model":"jev-1.13.0","answers":{"evaluation":{"type":"choice","choice":"NONE","probabilities":{"NONE":0.8,"UNKNOWN":0.2},"confidence":0.6}},"usage":{"input_tokens":120,"output_tokens":8}}"#;

    fn parse_input(value: &Value) -> Result<Input, &'static str> {
        Input::parse(&serde_json::to_vec(value).unwrap())
    }

    fn noul_input() -> Input {
        let mut value: Value = serde_json::from_str(CHOICE_INPUT).unwrap();
        value["question"] = json!({"type": "noul", "instructions": "Is the content risky?"});
        parse_input(&value).unwrap()
    }

    #[test]
    fn input_roundtrip_and_provider_body_keep_trust_and_evidence_explicit() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        assert_eq!(input.model_revision(), MODEL_REVISION);
        assert_eq!(input.policy_revision(), "policy-r1");
        assert_eq!(input.prompt_revision(), "prompt-r1");
        assert_eq!(input.question_type(), "choice");
        let internal: Value = serde_json::from_slice(&input.internal_bytes().unwrap()).unwrap();
        assert_eq!(
            internal,
            serde_json::from_str::<Value>(CHOICE_INPUT).unwrap()
        );
        let bytes = input
            .api_bytes(REQUEST_ID, MODEL_CALL_ID, ARTIFACT_ID)
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["model"], MODEL_REVISION);
        assert_eq!(body["questions"]["evaluation"], internal["question"]);
        assert_eq!(
            body["state"]["untrusted_content"],
            internal["untrusted_content"]
        );
        for field in ["auth_facts", "page_evidence"] {
            assert_eq!(body["state"][field]["status"], "unavailable");
            assert_eq!(body["state"]["coverage"][field], "unavailable");
        }
        assert_eq!(
            body["state"]["trusted_policy"]["scope"],
            "operator_approved_offline_evaluation"
        );
        assert_eq!(
            body["state"]["trace_context"],
            json!({"request_id": REQUEST_ID, "model_call_id": MODEL_CALL_ID,
                "input_artifact_id": ARTIFACT_ID})
        );
    }

    #[test]
    fn gateway_uses_alias_on_wire_but_keeps_internal_revision_unresolved() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        let bytes = input
            .api_bytes_for_model(REQUEST_ID, MODEL_CALL_ID, ARTIFACT_ID, GATEWAY_MODEL)
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["model"], GATEWAY_MODEL);
        let response = CHOICE_RESPONSE
            .replace("jev-1.13.0", GATEWAY_MODEL)
            .replace(
                "\"usage\":{",
                "\"provider_metadata\":{\"gateway\":{\"routing\":{\"originalModelId\":\"typesafe-ai/jev\",\"resolvedProvider\":\"typesafe-ai\",\"canonicalSlug\":\"typesafe-ai/jev\",\"finalProvider\":\"typesafe-ai\",\"generationId\":\"gen_1\",\"cost\":0.0}}},\"usage\":{",
            );
        let parsed = Response::parse_for_model(response.as_bytes(), &input, GATEWAY_MODEL).unwrap();
        assert_eq!(parsed.model_revision, MODEL_REVISION);
        assert_eq!(parsed.resolved_model_revision, None);
    }

    #[test]
    fn input_rejects_unapproved_shapes_versions_and_names() {
        for (field, replacement) in [
            ("schema_version", json!(2)),
            ("approval_ref", json!("https://example.invalid/approval")),
            ("approval_ref", json!("")),
            ("model_revision", json!("jev-latest")),
            ("model_revision", json!("jev-1.13.1")),
            ("policy_revision", json!("a".repeat(129))),
            ("prompt_revision", json!("prompt/r1")),
            ("untrusted_content", json!({"nested": "content"})),
            ("auth_facts", json!({"credential": "synthetic"})),
            ("tools", json!([])),
            ("url", json!("https://example.invalid")),
        ] {
            let mut value: Value = serde_json::from_str(CHOICE_INPUT).unwrap();
            value[field] = replacement;
            assert_eq!(parse_input(&value).err(), Some(INPUT_INVALID), "{field}");
        }
        for replacement in [
            json!({"type": "score", "instructions": "Evaluate."}),
            json!({"type": "noul", "instructions": "Evaluate.", "criteria": {}}),
            json!({"type": "noul", "instructions": {"nested": "Evaluate."}}),
        ] {
            let mut value: Value = serde_json::from_str(CHOICE_INPUT).unwrap();
            value["question"] = replacement;
            assert_eq!(parse_input(&value).err(), Some(INPUT_INVALID));
        }
    }

    #[test]
    fn input_rejects_duplicate_fields_and_candidates() {
        for (needle, replacement) in [
            (
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
            ),
            (
                "\"type\":\"choice\"",
                "\"type\":\"choice\",\"type\":\"choice\"",
            ),
            (
                "\"instructions\":",
                "\"instructions\":\"Other\",\"instructions\":",
            ),
            ("\"NONE\":", "\"NONE\":\"Other\",\"NONE\":"),
        ] {
            let bytes = CHOICE_INPUT.replace(needle, replacement);
            assert_eq!(Input::parse(bytes.as_bytes()).err(), Some(INPUT_INVALID));
        }
    }

    #[test]
    fn input_enforces_candidate_and_text_budgets() {
        for criteria in [
            json!({"NONE": "None"}),
            json!({"NONE": "None", "OTHER": "Other"}),
            json!({"NONE": "None", "UNKNOWN": "Unknown", "bad/key": "Bad"}),
            json!({"NONE": "None", "UNKNOWN": "Unknown", "候选": "Bad"}),
            json!({"NONE": "x".repeat(513), "UNKNOWN": "Unknown"}),
        ] {
            let mut value: Value = serde_json::from_str(CHOICE_INPUT).unwrap();
            value["question"]["criteria"] = criteria;
            assert_eq!(parse_input(&value).err(), Some(INPUT_INVALID));
        }
        let mut value: Value = serde_json::from_str(CHOICE_INPUT).unwrap();
        for index in 0..31 {
            value["question"]["criteria"][format!("OPTION_{index}")] = json!("Option");
        }
        assert_eq!(parse_input(&value).err(), Some(INPUT_INVALID));
        value = serde_json::from_str(CHOICE_INPUT).unwrap();
        value["question"]["instructions"] = json!("x".repeat(1_025));
        assert_eq!(parse_input(&value).err(), Some(INPUT_INVALID));
        value["question"]["instructions"] = json!("Choose.");
        value["untrusted_content"] = json!("x".repeat(TEXT_CHARS_MAX));
        assert_eq!(parse_input(&value).err(), Some(INPUT_INVALID));
        let mut oversized = CHOICE_INPUT.as_bytes().to_vec();
        oversized.resize(INPUT_BYTES_MAX + 1, b' ');
        assert_eq!(Input::parse(&oversized).err(), Some(INPUT_INVALID));
    }

    #[test]
    fn api_enforces_trace_ids_and_its_own_serialized_byte_budget() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        for (request, call, artifact) in [
            ("req_bad", MODEL_CALL_ID, ARTIFACT_ID),
            (REQUEST_ID, REQUEST_ID, ARTIFACT_ID),
            (REQUEST_ID, MODEL_CALL_ID, "artifact_bad"),
        ] {
            assert_eq!(
                input.api_bytes(request, call, artifact).err(),
                Some(INPUT_INVALID)
            );
        }
        let mut value: Value = serde_json::from_str(CHOICE_INPUT).unwrap();
        value["untrusted_content"] = json!("é".repeat(3_800));
        let input = parse_input(&value).unwrap();
        assert!(input.internal_bytes().unwrap().len() <= INPUT_BYTES_MAX);
        assert_eq!(
            input
                .api_bytes(REQUEST_ID, MODEL_CALL_ID, ARTIFACT_ID)
                .err(),
            Some(INPUT_INVALID)
        );
    }

    #[test]
    fn choice_preserves_reported_probabilities_confidence_and_usage() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        let response = Response::parse(CHOICE_RESPONSE.as_bytes(), &input).unwrap();
        assert!(matches!(&response.result, ResultValue::Choice(value) if value == "NONE"));
        assert_eq!(response.model_revision, MODEL_REVISION);
        assert_eq!(response.probabilities.len(), 2);
        assert_eq!(response.provider_confidence, Some(0.6));
        assert_eq!(response.confidence_status, "provided");
        assert_eq!(response.input_tokens, Some(120));
        assert_eq!(response.output_tokens, Some(8));
        assert_eq!(response.usage_source, "provider");
        assert_eq!(serde_json::to_value(&response).unwrap()["result"], "NONE");
    }

    #[test]
    fn choice_accepts_all_32_candidates_and_the_documented_text_edges() {
        let mut input: Value = serde_json::from_str(CHOICE_INPUT).unwrap();
        input["question"]["instructions"] = json!("x".repeat(1_024));
        input["question"]["criteria"]["NONE"] = json!("é".repeat(512));
        let mut probabilities =
            BTreeMap::from([("NONE".to_owned(), 0.0), ("UNKNOWN".to_owned(), 0.0)]);
        for index in 0..30 {
            let key = format!("OPTION_{index}");
            input["question"]["criteria"][&key] = json!("Candidate.");
            probabilities.insert(key, if index == 29 { 1.0 } else { 0.0 });
        }
        let input = parse_input(&input).unwrap();
        let bytes = serde_json::to_vec(&json!({
            "model": MODEL_REVISION,
            "answers": {"evaluation": {"type": "choice", "choice": "OPTION_29",
                "probabilities": probabilities}}
        }))
        .unwrap();
        let response = Response::parse(&bytes, &input).unwrap();
        assert_eq!(response.probabilities.len(), 32);
        assert!(matches!(&response.result, ResultValue::Choice(value) if value == "OPTION_29"));
        assert_eq!(response.provider_confidence, None);
    }

    #[test]
    fn missing_confidence_and_usage_stay_explicitly_unknown() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        for confidence in ["", ",\"confidence\":null"] {
            for usage in ["", ",\"usage\":null", ",\"usage\":{}"] {
                let bytes = format!(
                    r#"{{"model":"jev-1.13.0","answers":{{"evaluation":{{"type":"choice","choice":"NONE","probabilities":{{"NONE":1,"UNKNOWN":0}}{confidence}}}}}{usage}}}"#
                );
                let response = Response::parse(bytes.as_bytes(), &input).unwrap();
                assert_eq!(response.provider_confidence, None);
                assert_eq!(response.confidence_status, "not_provided");
                assert_eq!(response.input_tokens, None);
                assert_eq!(response.output_tokens, None);
                assert_eq!(response.usage_source, "unavailable");
            }
        }
        let bytes = CHOICE_RESPONSE.replace("\"input_tokens\":120,", "");
        let response = Response::parse(bytes.as_bytes(), &input).unwrap();
        assert_eq!(response.input_tokens, None);
        assert_eq!(response.output_tokens, Some(8));
        assert_eq!(response.usage_source, "provider");
    }

    #[test]
    fn choice_rejects_distribution_confidence_and_schema_mismatches() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        for (needle, replacement) in [
            ("\"model\":\"jev-1.13.0\"", "\"model\":\"jev-latest\""),
            ("\"evaluation\":", "\"unexpected\":"),
            ("\"choice\":\"NONE\"", "\"choice\":\"UNKNOWN\""),
            ("\"choice\":\"NONE\"", "\"choice\":\"OTHER\""),
            ("\"NONE\":0.8", "\"NONE\":0.7"),
            ("\"NONE\":0.8", "\"NONE\":1.1"),
            ("\"NONE\":0.8", "\"NONE\":-0.2"),
            ("\"NONE\":0.8", "\"NONE\":1e309"),
            ("\"NONE\":0.8", "\"NONE\":\"0.8\""),
            (",\"UNKNOWN\":0.2", ""),
            ("\"UNKNOWN\":0.2", "\"OTHER\":0.2"),
            ("\"UNKNOWN\":0.2", "\"UNKNOWN\":0.2,\"OTHER\":0"),
            ("\"confidence\":0.6", "\"confidence\":1.1"),
            ("\"confidence\":0.6", "\"confidence\":-0.1"),
            ("\"confidence\":0.6", "\"confidence\":\"0.6\""),
            ("\"confidence\":0.6", "\"confidence\":0.6,\"extra\":null"),
            ("\"input_tokens\":120", "\"input_tokens\":-1"),
            ("\"input_tokens\":120", "\"input_tokens\":1.5"),
            ("\"input_tokens\":120", "\"input_tokens\":\"120\""),
            (
                "\"input_tokens\":120",
                "\"input_tokens\":18446744073709551616",
            ),
            ("\"output_tokens\":8", "\"output_tokens\":8,\"cost\":1"),
        ] {
            let bytes = CHOICE_RESPONSE.replace(needle, replacement);
            assert_eq!(
                Response::parse(bytes.as_bytes(), &input).err(),
                Some(RESPONSE_INVALID),
                "{replacement}"
            );
        }
    }

    #[test]
    fn response_rejects_duplicates_at_every_object_boundary() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        for (needle, replacement) in [
            ("\"model\":", "\"model\":\"jev-1.13.0\",\"model\":"),
            (
                "\"evaluation\":",
                "\"evaluation\":{\"type\":\"noul\",\"noul\":0.5},\"evaluation\":",
            ),
            (
                "\"type\":\"choice\"",
                "\"type\":\"choice\",\"type\":\"choice\"",
            ),
            ("\"choice\":", "\"choice\":\"NONE\",\"choice\":"),
            ("\"NONE\":", "\"NONE\":0.8,\"NONE\":"),
            ("\"confidence\":", "\"confidence\":null,\"confidence\":"),
            ("\"usage\":", "\"usage\":null,\"usage\":"),
            (
                "\"input_tokens\":",
                "\"input_tokens\":null,\"input_tokens\":",
            ),
        ] {
            let bytes = CHOICE_RESPONSE.replace(needle, replacement);
            assert_eq!(
                Response::parse(bytes.as_bytes(), &input).err(),
                Some(RESPONSE_INVALID),
                "{replacement}"
            );
        }
    }

    #[test]
    fn noul_has_its_own_primitive_and_absent_confidence_semantics() {
        let input = noul_input();
        assert_eq!(input.question_type(), "noul");
        let bytes = br#"{"model":"jev-1.13.0","answers":{"evaluation":{"type":"noul","noul":0.25}},"usage":null}"#;
        let response = Response::parse(bytes, &input).unwrap();
        assert!(matches!(response.result, ResultValue::Noul(_)));
        assert!(response.probabilities.is_empty());
        assert_eq!(response.provider_confidence, None);
        assert_eq!(response.confidence_status, "not_applicable");
        assert_eq!(response.usage_source, "unavailable");
        assert_eq!(serde_json::to_value(&response).unwrap()["result"], 0.25);
        assert_eq!(
            Response::parse(CHOICE_RESPONSE.as_bytes(), &input).err(),
            Some(RESPONSE_INVALID)
        );
        let choice_input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        assert_eq!(
            Response::parse(bytes, &choice_input).err(),
            Some(RESPONSE_INVALID)
        );
        let source = std::str::from_utf8(bytes).unwrap();
        for replacement in [
            "-0.1",
            "1.1",
            "null",
            "\"0.25\"",
            "0.25,\"confidence\":null",
            "0.25,\"noul\":0.25",
        ] {
            let bytes = source.replace("0.25", replacement);
            assert_eq!(
                Response::parse(bytes.as_bytes(), &input).err(),
                Some(RESPONSE_INVALID)
            );
        }
    }

    #[test]
    fn response_requires_one_bounded_complete_json_document() {
        let input = Input::parse(CHOICE_INPUT.as_bytes()).unwrap();
        let mut oversized = CHOICE_RESPONSE.as_bytes().to_vec();
        oversized.resize(RESPONSE_BYTES_MAX + 1, b' ');
        assert_eq!(
            Response::parse(&oversized, &input).err(),
            Some(RESPONSE_INVALID)
        );
        let trailing = format!("{CHOICE_RESPONSE}{{}}");
        assert_eq!(
            Response::parse(trailing.as_bytes(), &input).err(),
            Some(RESPONSE_INVALID)
        );
    }
}
