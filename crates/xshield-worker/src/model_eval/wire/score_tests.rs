//! Score conversion tests exercise ordered-scale and probability boundaries.

use super::*;
use serde_json::{Value, json};

const REQUEST_ID: &str = "req_01a0afa6-3320-7791-8f45-b4d5a34ffb57";
const MODEL_CALL_ID: &str = "mdl_01a0afa6-3320-7791-8f45-b4d5a34ffb58";
const ARTIFACT_ID: &str = "artifact_01a0afa6-3320-7791-8f45-b4d5a34ffb59";

fn input_value() -> Value {
    json!({"schema_version":1,"approval_ref":"approval-r1",
        "model_revision":"jev-1.13.0","policy_revision":"policy-r1",
        "prompt_revision":"prompt-r1","untrusted_content":"Synthetic content.",
        "question":{"type":"score","instructions":"Rate severity.",
            "criteria":["Low","Medium","High"]}})
}

fn input(value: &Value) -> Result<Input, &'static str> {
    Input::parse(&serde_json::to_vec(value).unwrap())
}

fn answer_value() -> Value {
    json!({"model":DIRECT_MODEL,"answers":{"evaluation":{"type":"score",
        "score":1.43,"legend":{"0":"Low","1":"Medium","2":"High"},
        "probabilities":{"0":0.0,"1":0.57,"2":0.43},"confidence":0.35}}})
}

#[test]
fn score_preserves_ordered_scale_expected_value_and_provider_confidence() {
    let value = input_value();
    let approved = input(&value).unwrap();
    assert_eq!(approved.question_type(), "score");
    for model in [DIRECT_MODEL, GATEWAY_MODEL] {
        let sent: Value = serde_json::from_slice(
            &approved
                .api_bytes_for_model(REQUEST_ID, MODEL_CALL_ID, ARTIFACT_ID, model)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(sent["questions"]["evaluation"], value["question"]);
        assert_eq!(sent["model"], model);
        let mut answer = answer_value();
        answer["model"] = model.into();
        let response =
            Response::parse_for_model(&serde_json::to_vec(&answer).unwrap(), &approved, model)
                .unwrap();
        assert!(
            matches!(response.result, ResultValue::Score(value) if (value - 1.43).abs() < f64::EPSILON)
        );
        assert_eq!(response.provider_confidence, Some(0.35));
        assert_eq!(response.confidence_status, "provided");
        assert_eq!(response.probabilities.len(), 3);
        assert_eq!(response.legend.unwrap()["2"], "High");
        assert_eq!(
            response.resolved_model_revision,
            (model == DIRECT_MODEL).then(|| DIRECT_MODEL.to_owned())
        );
        assert_eq!(response.usage_source, "unavailable");
    }
}

#[test]
fn score_input_bounds_and_types_are_enforced() {
    for criteria in [
        json!([]),
        json!(["Only"]),
        json!(vec!["x"; 11]),
        json!(["", "High"]),
        json!(["x".repeat(513), "High"]),
        json!([null, "High"]),
        json!({"0":"Low","1":"High"}),
    ] {
        let mut value = input_value();
        value["question"]["criteria"] = criteria;
        assert_eq!(input(&value).err(), Some(INPUT_INVALID));
    }
    for count in [2, 10] {
        let mut value = input_value();
        value["question"]["criteria"] =
            json!((0..count).map(|i| format!("Level {i}")).collect::<Vec<_>>());
        assert!(input(&value).is_ok());
    }
    let mut value = input_value();
    value["untrusted_content"] = json!("x".repeat(TEXT_CHARS_MAX));
    assert_eq!(input(&value).err(), Some(INPUT_INVALID));
    let mut value = input_value();
    value["question"]["max"] = 10.into();
    assert_eq!(input(&value).err(), Some(INPUT_INVALID));
}

#[test]
fn score_rejects_scale_distribution_and_primitive_substitution() {
    let approved = input(&input_value()).unwrap();
    for (field, bad) in [
        ("score", json!(1)),
        ("score", json!(-0.1)),
        ("score", json!(2.1)),
        ("score", json!("1.43")),
        ("score", json!(null)),
        ("legend", json!({"0":"Low","1":"Changed","2":"High"})),
        ("legend", json!({"0":"Low","1":"Medium"})),
        ("legend", json!({"0":"Low","1":"Medium","02":"High"})),
        ("probabilities", json!({"0":0,"1":0.6,"2":0.5})),
        ("probabilities", json!({"0":-0.1,"1":0.67,"2":0.43})),
        ("probabilities", json!({"0":0,"1":0.57,"2":0.43,"3":0})),
        ("probabilities", json!({"0":0,"1":1})),
        ("confidence", json!(1.1)),
        ("confidence", json!(-0.1)),
        ("type", json!("choice")),
        ("type", json!("noul")),
    ] {
        let mut answer = answer_value();
        answer["answers"]["evaluation"][field] = bad;
        assert_eq!(
            Response::parse(&serde_json::to_vec(&answer).unwrap(), &approved).err(),
            Some(RESPONSE_INVALID),
            "{field}"
        );
    }
    let answer = answer_value().to_string();
    for (from, to) in [
        ("\"score\":1.43", "\"score\":1e309"),
        ("\"score\":1.43", "\"score\":1.43,\"score\":1.43"),
        ("\"0\":\"Low\"", "\"0\":\"Low\",\"0\":\"Low\""),
        ("\"0\":0.0", "\"0\":0.0,\"0\":0.0"),
    ] {
        assert!(answer.contains(from));
        assert_eq!(
            Response::parse(answer.replace(from, to).as_bytes(), &approved).err(),
            Some(RESPONSE_INVALID)
        );
    }
}

#[test]
fn score_edges_rounding_and_missing_confidence_keep_exact_semantics() {
    for levels in [2_u32, 10] {
        let mut value = input_value();
        let descriptions = (0..levels)
            .map(|i| format!("Level {i}"))
            .collect::<Vec<_>>();
        value["question"]["criteria"] = json!(descriptions);
        let approved = input(&value).unwrap();
        for selected in [0, levels - 1] {
            let legend = descriptions
                .iter()
                .enumerate()
                .map(|(i, s)| (i.to_string(), s))
                .collect::<BTreeMap<_, _>>();
            let probabilities = (0..levels)
                .map(|i| (i.to_string(), f64::from(u8::from(i == selected))))
                .collect::<BTreeMap<_, _>>();
            let answer = json!({"model":DIRECT_MODEL,"answers":{"evaluation":{
                "type":"score","score":selected,"legend":legend,"probabilities":probabilities}}});
            let response =
                Response::parse(&serde_json::to_vec(&answer).unwrap(), &approved).unwrap();
            assert_eq!(response.provider_confidence, None);
            assert_eq!(response.confidence_status, "not_provided");
        }
    }
    let approved = input(&input_value()).unwrap();
    for (offset, valid) in [(0.000_001, true), (0.000_1, false)] {
        let mut answer = answer_value();
        answer["answers"]["evaluation"]["score"] = json!(1.43 + offset);
        answer["answers"]["evaluation"]["confidence"] = Value::Null;
        assert_eq!(
            Response::parse(&serde_json::to_vec(&answer).unwrap(), &approved).is_ok(),
            valid
        );
    }
}
