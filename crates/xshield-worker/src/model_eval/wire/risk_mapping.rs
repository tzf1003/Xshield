//! Explicit operator-approved projection of complete provider distributions.
//!
//! The internal input evidence binds the mapping revision and class assignments.
//! A projection is descriptive model evidence and grants no authorization.

use super::{INPUT_INVALID, Question, RESPONSE_INVALID, unique_options};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use xshield_core::calibration::{
    Probability, Signal,
    mapping::{ApprovedRiskMapping, RiskClass},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MappingDto {
    revision: String,
    #[serde(deserialize_with = "unique_options")]
    classes: BTreeMap<String, ClassDto>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClassDto {
    Benign,
    Malicious,
    Unknown,
}

impl MappingDto {
    pub(super) fn text_chars(&self) -> usize {
        self.revision.chars().count()
            + self
                .classes
                .keys()
                .map(|key| key.chars().count())
                .sum::<usize>()
    }
    fn domain(&self) -> Result<ApprovedRiskMapping, &'static str> {
        ApprovedRiskMapping::new(
            self.revision.clone(),
            self.classes
                .iter()
                .map(|(key, class)| {
                    (
                        key.clone(),
                        match class {
                            ClassDto::Benign => RiskClass::Benign,
                            ClassDto::Malicious => RiskClass::Malicious,
                            ClassDto::Unknown => RiskClass::Unknown,
                        },
                    )
                })
                .collect(),
        )
        .map_err(|_| INPUT_INVALID)
    }

    pub(super) fn validate(&self, question: &Question) -> Result<(), &'static str> {
        self.domain()?;
        let keys: Vec<_> = match question {
            Question::Choice { criteria, .. } => criteria.keys().cloned().collect(),
            Question::Score { criteria, .. } => {
                (0..criteria.len()).map(|i| i.to_string()).collect()
            }
            Question::Noul { .. } => return Err(INPUT_INVALID),
        };
        if !self.classes.keys().eq(keys.iter()) {
            return Err(INPUT_INVALID);
        }
        // Choice's explicit uncertainty candidate must keep its mass visible as
        // uncertainty. It cannot be relabeled to force a numerical risk decision.
        if matches!(question, Question::Choice { .. })
            && !matches!(self.classes.get("UNKNOWN"), Some(ClassDto::Unknown))
        {
            return Err(INPUT_INVALID);
        }
        Ok(())
    }

    pub(super) fn project(
        &self,
        probabilities: &BTreeMap<String, f64>,
    ) -> Result<RiskProjection, &'static str> {
        let mapping = self.domain().map_err(|_| RESPONSE_INVALID)?;
        let distribution = probabilities
            .iter()
            .map(|(key, value)| {
                Probability::new(*value)
                    .map(|p| (key.clone(), p))
                    .map_err(|_| RESPONSE_INVALID)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let projection = mapping
            .project(&distribution)
            .map_err(|_| RESPONSE_INVALID)?;
        let abstained = matches!(projection.signal(), Signal::Unavailable(_));
        Ok(RiskProjection {
            mapping_revision: projection.revision().to_owned(),
            malicious_probability: projection.malicious_probability(),
            benign_probability: projection.benign_probability(),
            unknown_probability: projection.unknown_probability(),
            abstained,
            reason_code: if abstained {
                "MODEL_RISK_ABSTAINED"
            } else {
                "MODEL_RISK_PROJECTED"
            },
        })
    }
}

/// Optional descriptive projection retained with the complete model-call record.
#[derive(Clone, Serialize)]
pub(crate) struct RiskProjection {
    mapping_revision: String,
    malicious_probability: f64,
    benign_probability: f64,
    unknown_probability: f64,
    abstained: bool,
    reason_code: &'static str,
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::{Value, json};

    fn input_value() -> Value {
        json!({"schema_version":1,"approval_ref":"approval-r1","model_revision":"jev-1.13.0",
            "policy_revision":"policy-r1","prompt_revision":"prompt-r1","untrusted_content":"synthetic",
            "question":{"type":"choice","instructions":"Classify.","criteria":{"NONE":"benign","RISK":"malicious","UNKNOWN":"uncertain"}},
            "risk_mapping":{"revision":"risk-map-r1","classes":{"NONE":"benign","RISK":"malicious","UNKNOWN":"unknown"}}})
    }

    #[test]
    fn projection_keeps_uncertainty_and_confidence_separate() {
        let input = Input::parse(&serde_json::to_vec(&input_value()).unwrap()).unwrap();
        let internal: Value = serde_json::from_slice(&input.internal_bytes().unwrap()).unwrap();
        assert_eq!(internal["risk_mapping"], input_value()["risk_mapping"]);
        let api: Value = serde_json::from_slice(
            &input
                .api_bytes(
                    "req_018f2a3b-4c5d-7000-8000-000000000001",
                    "mdl_018f2a3b-4c5d-7000-8000-000000000002",
                    "artifact_018f2a3b-4c5d-7000-8000-000000000003",
                )
                .unwrap(),
        )
        .unwrap();
        assert!(api.get("risk_mapping").is_none());
        assert_eq!(api["questions"]["evaluation"], internal["question"]);
        for (risk, unknown, abstained) in [(0.2, 0.0, false), (0.1, 0.1, true)] {
            let response = json!({"model":DIRECT_MODEL,"answers":{"evaluation":{
                "type":"choice","choice":"NONE","probabilities":{"NONE":0.8,"RISK":risk,"UNKNOWN":unknown},"confidence":0.99}}});
            let parsed = Response::parse(&serde_json::to_vec(&response).unwrap(), &input).unwrap();
            let projection = serde_json::to_value(parsed.risk_projection.unwrap()).unwrap();
            assert_eq!(projection["mapping_revision"], "risk-map-r1");
            assert_eq!(projection["malicious_probability"], risk);
            assert_eq!(projection["unknown_probability"], unknown);
            assert_eq!(projection["abstained"], abstained);
            assert_eq!(parsed.provider_confidence, Some(0.99));
        }
    }

    #[test]
    fn score_mapping_accepts_all_ten_ordered_levels() {
        let mut value = input_value();
        value["question"] = json!({"type":"score","instructions":"Rate.",
            "criteria":(0..10).map(|i| format!("Level {i}")).collect::<Vec<_>>()});
        value["risk_mapping"]["classes"] = json!(
            (0..10)
                .map(|i| (i.to_string(), if i == 9 { "malicious" } else { "benign" }))
                .collect::<BTreeMap<_, _>>()
        );
        let input = Input::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let response = json!({"model":DIRECT_MODEL,"answers":{"evaluation":{
            "type":"score","score":9,
            "legend":(0..10).map(|i| (i.to_string(),format!("Level {i}"))).collect::<BTreeMap<_,_>>(),
            "probabilities":(0..10).map(|i| (i.to_string(),u8::from(i==9))).collect::<BTreeMap<_,_>>()}}});
        let parsed = Response::parse(&serde_json::to_vec(&response).unwrap(), &input).unwrap();
        let projection = serde_json::to_value(parsed.risk_projection.unwrap()).unwrap();
        assert_eq!(projection["malicious_probability"], 1.0);
        assert_eq!(projection["abstained"], false);
    }

    #[test]
    fn mapping_requires_complete_approved_classes_and_uncertainty() {
        for classes in [
            json!({"NONE":"benign","RISK":"malicious"}),
            json!({"NONE":"benign","RISK":"malicious","UNKNOWN":"benign"}),
            json!({"NONE":"benign","RISK":"unknown","UNKNOWN":"unknown"}),
            json!({"NONE":"benign","RISK":"malicious","UNKNOWN":"unknown","EXTRA":"benign"}),
        ] {
            let mut value = input_value();
            value["risk_mapping"]["classes"] = classes;
            assert_eq!(
                Input::parse(&serde_json::to_vec(&value).unwrap()).err(),
                Some(INPUT_INVALID)
            );
        }
        let mut value = input_value();
        value["question"] = json!({"type":"noul","instructions":"Evaluate."});
        assert_eq!(
            Input::parse(&serde_json::to_vec(&value).unwrap()).err(),
            Some(INPUT_INVALID)
        );
        let mut value = input_value();
        value["risk_mapping"]["revision"] = json!("bad/revision");
        assert_eq!(
            Input::parse(&serde_json::to_vec(&value).unwrap()).err(),
            Some(INPUT_INVALID)
        );
    }
}
