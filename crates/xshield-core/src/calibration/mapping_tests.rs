#![allow(clippy::float_cmp)] // Exact binary fixtures and preservation of original mass are the contract.

use super::*;

fn mapping() -> ApprovedRiskMapping {
    ApprovedRiskMapping::new(
        "risk.v1".into(),
        vec![
            ("0".into(), RiskClass::Benign),
            ("1".into(), RiskClass::Malicious),
            ("2".into(), RiskClass::Unknown),
        ],
    )
    .unwrap()
}
fn distribution(values: &[f64]) -> Vec<(String, Probability)> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| (index.to_string(), Probability::new(*value).unwrap()))
        .collect()
}

#[test]
fn equal_score_means_preserve_different_risk_and_unknown_mass() {
    let middle = mapping().project(&distribution(&[0.0, 1.0, 0.0])).unwrap();
    let extremes = mapping().project(&distribution(&[0.5, 0.0, 0.5])).unwrap();
    // Both ordinal expectations are one; their approved risk meanings differ.
    assert_eq!(
        middle.signal(),
        Signal::Risk(Probability::new(1.0).unwrap())
    );
    assert_eq!(
        extremes.signal(),
        Signal::Unavailable(UnavailableReason::ProbabilityMissing)
    );
    assert_eq!(extremes.benign_probability(), 0.5);
    assert_eq!(extremes.malicious_probability(), 0.0);
    assert_eq!(extremes.unknown_probability(), 0.5);
    assert_eq!(extremes.revision(), "risk.v1");
    assert_eq!(extremes.reason_code(), "RISK_MAPPING_ABSTAINED");
    assert_eq!(middle.reason_code(), "RISK_MAPPING_PROJECTED");
}

#[test]
fn any_positive_unknown_mass_abstains_without_renormalization() {
    for unknown in [f64::from_bits(1), 0.1, 1.0] {
        let result = mapping()
            .project(&distribution(&[0.0, 1.0 - unknown, unknown]))
            .unwrap();
        assert_eq!(result.unknown_probability(), unknown);
        assert_eq!(result.malicious_probability(), 1.0 - unknown);
        assert_eq!(
            result.signal(),
            Signal::Unavailable(UnavailableReason::ProbabilityMissing)
        );
    }
}

#[test]
fn rejects_duplicate_missing_and_extra_distribution_keys() {
    let approved = mapping();
    let mut duplicate = distribution(&[0.5, 0.5, 0.0]);
    duplicate[2].0 = "1".into();
    assert_eq!(
        approved.project(&duplicate),
        Err(MappingError::DuplicateOutcome)
    );
    assert_eq!(
        approved.project(&distribution(&[0.5, 0.5])),
        Err(MappingError::MissingOutcome)
    );
    let mut extra = distribution(&[0.5, 0.5, 0.0]);
    extra[2].0 = "extra".into();
    assert_eq!(approved.project(&extra), Err(MappingError::ExtraOutcome));
    assert_eq!(
        approved.project(&distribution(&[0.0; 33])),
        Err(MappingError::InvalidOutcomeCount)
    );
}

#[test]
fn validates_serialization_tolerance_without_rescaling() {
    let approved = mapping();
    for total in [0.0, 0.99, 1.000_002] {
        assert_eq!(
            approved.project(&distribution(&[total / 2.0, total / 2.0, 0.0])),
            Err(MappingError::InvalidTotalMass)
        );
    }
    for total in [0.999_999_5, 1.000_000_5] {
        let result = approved
            .project(&distribution(&[total / 2.0, total / 2.0, 0.0]))
            .unwrap();
        assert_eq!(result.benign_probability(), total / 2.0);
        assert_eq!(result.malicious_probability(), total / 2.0);
    }
}

#[test]
fn scoped_names_revision_and_required_classes_are_checked() {
    let assignments = vec![
        ("safe".into(), RiskClass::Benign),
        ("bad".into(), RiskClass::Malicious),
    ];
    for invalid in [
        String::new(),
        "汉字".into(),
        "has space".into(),
        "a/b".into(),
        "a".repeat(129),
    ] {
        assert_eq!(
            ApprovedRiskMapping::new(invalid.clone(), assignments.clone()),
            Err(MappingError::InvalidRevision)
        );
        assert_eq!(
            ApprovedRiskMapping::new(
                "v1".into(),
                vec![
                    (invalid, RiskClass::Benign),
                    ("bad".into(), RiskClass::Malicious)
                ]
            ),
            Err(MappingError::InvalidOutcomeName)
        );
    }
    let valid = ApprovedRiskMapping::new(
        "a".repeat(128),
        vec![
            ("a".repeat(128), RiskClass::Benign),
            ("A_1-.".into(), RiskClass::Malicious),
        ],
    )
    .unwrap();
    assert_eq!(valid.revision().len(), 128);
    assert_eq!(
        ApprovedRiskMapping::new("v1".into(), vec![]),
        Err(MappingError::InvalidOutcomeCount)
    );
    assert_eq!(
        ApprovedRiskMapping::new("v1".into(), vec![("a".into(), RiskClass::Benign)]),
        Err(MappingError::InvalidOutcomeCount)
    );
    assert_eq!(
        ApprovedRiskMapping::new(
            "v1".into(),
            vec![
                ("a".into(), RiskClass::Benign),
                ("a".into(), RiskClass::Malicious)
            ]
        ),
        Err(MappingError::DuplicateOutcome)
    );
    for class in [RiskClass::Benign, RiskClass::Malicious, RiskClass::Unknown] {
        assert_eq!(
            ApprovedRiskMapping::new(
                "v1".into(),
                vec![("a".into(), class), ("b".into(), RiskClass::Unknown)]
            ),
            Err(MappingError::MissingRequiredClass)
        );
    }
}

#[test]
fn maximum_capacity_and_order_independence() {
    let assignments = (0..32)
        .map(|i| {
            (
                i.to_string(),
                if i == 0 {
                    RiskClass::Benign
                } else {
                    RiskClass::Malicious
                },
            )
        })
        .collect();
    let approved = ApprovedRiskMapping::new("v1".into(), assignments).unwrap();
    let values = distribution(&[1.0 / 32.0; 32]);
    let result = approved.project(&values).unwrap();
    assert_eq!(result.malicious_probability(), 31.0 / 32.0);
    let reversed = values.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(approved.project(&reversed).unwrap(), result);
    let oversized = (0..33)
        .map(|i| (i.to_string(), RiskClass::Benign))
        .collect();
    assert_eq!(
        ApprovedRiskMapping::new("v1".into(), oversized),
        Err(MappingError::InvalidOutcomeCount)
    );
}

#[test]
fn roundoff_is_retained_but_only_arithmetic_excess_can_be_clamped() {
    let approved = ApprovedRiskMapping::new(
        "v1".into(),
        vec![
            ("0".into(), RiskClass::Benign),
            ("1".into(), RiskClass::Malicious),
            ("2".into(), RiskClass::Malicious),
        ],
    )
    .unwrap();
    let result = approved
        .project(&distribution(&[0.0, 0.7, 0.300_000_000_000_000_2]))
        .unwrap();
    assert!(result.malicious_probability() > 1.0);
    assert_eq!(
        result.signal(),
        Signal::Risk(Probability::new(1.0).unwrap())
    );
    assert_eq!(
        approved.project(&distribution(&[0.0, 0.7, 0.300_000_1])),
        Err(MappingError::InvalidClassMass)
    );
    for values in [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]] {
        let result = approved.project(&distribution(&values)).unwrap();
        assert_eq!(
            result.signal(),
            Signal::Risk(Probability::new(values[1]).unwrap())
        );
    }
}

#[test]
fn error_codes_are_stable_and_payload_free() {
    let cases = [
        (
            MappingError::InvalidRevision,
            "RISK_MAPPING_REVISION_INVALID",
        ),
        (
            MappingError::InvalidOutcomeCount,
            "RISK_MAPPING_OUTCOME_COUNT_INVALID",
        ),
        (
            MappingError::InvalidOutcomeName,
            "RISK_MAPPING_OUTCOME_NAME_INVALID",
        ),
        (
            MappingError::DuplicateOutcome,
            "RISK_MAPPING_OUTCOME_DUPLICATE",
        ),
        (
            MappingError::MissingRequiredClass,
            "RISK_MAPPING_REQUIRED_CLASS_MISSING",
        ),
        (MappingError::MissingOutcome, "RISK_MAPPING_OUTCOME_MISSING"),
        (MappingError::ExtraOutcome, "RISK_MAPPING_OUTCOME_EXTRA"),
        (
            MappingError::InvalidTotalMass,
            "RISK_MAPPING_TOTAL_MASS_INVALID",
        ),
        (
            MappingError::InvalidClassMass,
            "RISK_MAPPING_CLASS_MASS_INVALID",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.reason_code(), code);
        assert_eq!(error.to_string(), code);
    }
}
