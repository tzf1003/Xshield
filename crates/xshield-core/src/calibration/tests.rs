use super::*;

fn probability(value: f64) -> Probability {
    Probability::new(value).unwrap()
}
fn thresholds() -> Thresholds {
    Thresholds::new(probability(0.2), probability(0.8)).unwrap()
}
fn sample(index: usize, ground_truth: GroundTruth, signal: Signal) -> Sample {
    Sample {
        model_call_id: ModelCallId::parse(format!("mdl_01a0afa6-3320-7791-8f45-{index:012x}"))
            .unwrap(),
        ground_truth,
        signal,
    }
}
fn risk(index: usize, label: GroundTruth, value: f64) -> Sample {
    sample(index, label, Signal::Risk(probability(value)))
}
fn close(actual: Option<f64>, expected: f64) {
    assert!((actual.unwrap() - expected).abs() < 1e-12);
}

#[test]
fn validates_probabilities_and_disjoint_thresholds() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.01, 1.01] {
        assert_eq!(
            Probability::new(value),
            Err(CalibrationError::InvalidProbability)
        );
    }
    for value in [0.0, -0.0, 1.0] {
        assert!(Probability::new(value).is_ok());
    }
    for (low, high) in [(0.8, 0.2), (0.5, 0.5)] {
        assert_eq!(
            Thresholds::new(probability(low), probability(high)),
            Err(CalibrationError::InvalidThresholds)
        );
    }
    assert_eq!(thresholds().allow_below_or_equal(), probability(0.2));
    assert_eq!(thresholds().deny_above_or_equal(), probability(0.8));
}

#[test]
fn six_cells_include_exact_inclusive_boundaries_and_missing_denominators() {
    let mut samples = Vec::new();
    for label in [GroundTruth::Benign, GroundTruth::Malicious] {
        for value in [0.2, 0.8, 0.5] {
            samples.push(risk(samples.len(), label, value));
        }
        samples.push(sample(
            samples.len(),
            label,
            Signal::Unavailable(UnavailableReason::ProbabilityMissing),
        ));
    }
    let report = evaluate(&samples, thresholds()).unwrap();
    assert_eq!(
        report.counts,
        ConfusionCounts {
            benign_allow: 1,
            benign_deny: 1,
            benign_abstain: 2,
            malicious_allow: 1,
            malicious_deny: 1,
            malicious_abstain: 2,
            ..ConfusionCounts::default()
        }
    );
    assert_eq!(
        report.false_allow_rate,
        Rate {
            numerator: 1,
            denominator: 4
        }
    );
    assert_eq!(
        report.false_deny_rate,
        Rate {
            numerator: 1,
            denominator: 4
        }
    );
    assert_eq!(
        report.coverage,
        Rate {
            numerator: 4,
            denominator: 8
        }
    );
    assert_eq!(
        report.unknown_rate,
        Rate {
            numerator: 4,
            denominator: 8
        }
    );
    assert_eq!(
        (
            report.available_samples,
            report.missing_samples,
            report.scored_samples
        ),
        (6, 2, 6)
    );
    close(report.brier_score, 0.31);
}

#[test]
fn unknown_labels_affect_coverage_but_not_supervised_metrics() {
    let samples = [
        risk(0, GroundTruth::Unknown, 0.0),
        risk(1, GroundTruth::Unknown, 1.0),
        risk(2, GroundTruth::Unknown, 0.5),
        sample(
            3,
            GroundTruth::Unknown,
            Signal::Unavailable(UnavailableReason::ModelFailed),
        ),
    ];
    let report = evaluate(&samples, thresholds()).unwrap();
    assert_eq!(
        (
            report.unknown_label_samples,
            report.available_samples,
            report.scored_samples
        ),
        (4, 3, 0)
    );
    assert_eq!(
        (
            report.counts.unknown_allow,
            report.counts.unknown_deny,
            report.counts.unknown_abstain
        ),
        (1, 1, 2)
    );
    close(report.coverage.value(), 0.5);
    assert_eq!(report.brier_score, None);
    assert_eq!(report.false_allow_rate.value(), None);
    assert_eq!(report.false_deny_rate.value(), None);
    assert!(
        report
            .reliability
            .iter()
            .all(|bin| bin.count == 0 && bin.mean_probability.is_none())
    );
}

#[test]
fn unavailable_reasons_remain_separate_and_do_not_score_as_zero() {
    let samples: Vec<_> = [
        UnavailableReason::ModelFailed,
        UnavailableReason::ModelTimedOut,
        UnavailableReason::ModelCancelled,
        UnavailableReason::ProbabilityMissing,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, reason)| sample(i, GroundTruth::Malicious, Signal::Unavailable(reason)))
    .collect();
    let report = evaluate(&samples, thresholds()).unwrap();
    assert_eq!(
        report.unavailable_counts,
        UnavailableCounts {
            model_failed: 1,
            model_timed_out: 1,
            model_cancelled: 1,
            probability_missing: 1
        }
    );
    assert_eq!(
        report.false_allow_rate,
        Rate {
            numerator: 0,
            denominator: 4
        }
    );
    assert_eq!(report.false_deny_rate.value(), None);
    assert_eq!(
        report.unknown_rate,
        Rate {
            numerator: 4,
            denominator: 4
        }
    );
    assert_eq!(report.brier_score, None);
}

#[test]
fn brier_and_reliability_use_only_known_available_samples() {
    let samples = [
        risk(0, GroundTruth::Benign, 0.25),
        risk(1, GroundTruth::Malicious, 0.75),
        risk(2, GroundTruth::Unknown, 0.95),
        sample(
            3,
            GroundTruth::Malicious,
            Signal::Unavailable(UnavailableReason::ModelTimedOut),
        ),
    ];
    let report = evaluate(&samples, thresholds()).unwrap();
    assert_eq!(report.scored_samples, 2);
    close(report.brier_score, 0.0625);
    assert_eq!(report.reliability[2].observed_positives, 0);
    assert_eq!(report.reliability[7].observed_positives, 1);
    close(report.reliability[2].mean_probability, 0.25);
    close(report.reliability[7].mean_probability, 0.75);
    assert_eq!(
        report.reliability.iter().map(|bin| bin.count).sum::<u32>(),
        2
    );
}

#[test]
fn all_bin_edges_and_immediately_lower_values_are_stable() {
    let mut samples = vec![risk(0, GroundTruth::Benign, 0.0)];
    for edge in BIN_UPPER_BOUNDS {
        samples.push(risk(
            samples.len(),
            GroundTruth::Malicious,
            edge.next_down(),
        ));
        samples.push(risk(samples.len(), GroundTruth::Malicious, edge));
    }
    let report = evaluate(&samples, thresholds()).unwrap();
    for (i, bin) in report.reliability.iter().enumerate() {
        assert_eq!(bin.count, if i == 9 { 3 } else { 2 });
    }
    assert_eq!(report.reliability[0].observed_positives, 1);
    assert_eq!(report.reliability[9].observed_positives, 3);
}

#[test]
fn enforces_empty_duplicate_and_capacity_bounds() {
    assert_eq!(
        evaluate(&[], thresholds()),
        Err(CalibrationError::EmptySamples)
    );
    let one = risk(0, GroundTruth::Benign, 0.1);
    assert_eq!(
        evaluate(&[one.clone(), one], thresholds()),
        Err(CalibrationError::DuplicateModelCallId)
    );
    let mut samples: Vec<_> = (0..MAX_SAMPLES)
        .map(|i| risk(i, GroundTruth::Benign, 0.0))
        .collect();
    assert_eq!(
        evaluate(&samples, thresholds()).unwrap().total_samples,
        10_000
    );
    samples.push(risk(MAX_SAMPLES, GroundTruth::Benign, 0.0));
    assert_eq!(
        evaluate(&samples, thresholds()),
        Err(CalibrationError::TooManySamples)
    );
}

#[test]
fn reason_codes_are_stable_and_errors_implement_standard_error() {
    let errors = [
        (
            CalibrationError::InvalidProbability,
            "CALIBRATION_PROBABILITY_INVALID",
        ),
        (
            CalibrationError::InvalidThresholds,
            "CALIBRATION_THRESHOLDS_INVALID",
        ),
        (CalibrationError::EmptySamples, "CALIBRATION_SAMPLES_EMPTY"),
        (
            CalibrationError::TooManySamples,
            "CALIBRATION_SAMPLE_LIMIT_EXCEEDED",
        ),
        (
            CalibrationError::DuplicateModelCallId,
            "CALIBRATION_MODEL_CALL_DUPLICATE",
        ),
    ];
    for (error, code) in errors {
        assert_eq!(error.reason_code(), code);
        let standard: &dyn std::error::Error = &error;
        assert_eq!(standard.to_string(), code);
    }
    assert_eq!(
        evaluate(&[risk(0, GroundTruth::Benign, 0.0)], thresholds())
            .unwrap()
            .reason_code(),
        "CALIBRATION_EVALUATED"
    );
}
