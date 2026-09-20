//! Public API regression with independently calculated reference metrics.

use xshield_core::{
    calibration::{
        GroundTruth, Probability, Sample, Signal, Thresholds, UnavailableReason, evaluate,
    },
    domain::ModelCallId,
};

fn sample(index: usize, ground_truth: GroundTruth, probability: Option<f64>) -> Sample {
    Sample {
        model_call_id: ModelCallId::parse(format!("mdl_018f2a3b-4c5d-7000-8000-{index:012x}"))
            .unwrap(),
        ground_truth,
        signal: probability.map_or(
            Signal::Unavailable(UnavailableReason::ModelTimedOut),
            |value| Signal::Risk(Probability::new(value).unwrap()),
        ),
    }
}

#[test]
fn missing_predictions_and_unknown_labels_have_distinct_denominators() {
    let samples = [
        sample(0, GroundTruth::Benign, Some(0.1)),
        sample(1, GroundTruth::Malicious, Some(0.9)),
        sample(2, GroundTruth::Malicious, Some(0.1)),
        sample(3, GroundTruth::Benign, Some(0.9)),
        sample(4, GroundTruth::Malicious, None),
        sample(5, GroundTruth::Unknown, Some(0.5)),
    ];
    let report = evaluate(
        &samples,
        Thresholds::new(
            Probability::new(0.2).unwrap(),
            Probability::new(0.8).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        (
            report.false_allow_rate.numerator,
            report.false_allow_rate.denominator
        ),
        (1, 3)
    );
    assert_eq!(
        (
            report.false_deny_rate.numerator,
            report.false_deny_rate.denominator
        ),
        (1, 2)
    );
    assert_eq!(
        (report.coverage.numerator, report.coverage.denominator),
        (4, 6)
    );
    assert_eq!(
        (
            report.unknown_rate.numerator,
            report.unknown_rate.denominator
        ),
        (2, 6)
    );
    assert_eq!(report.scored_samples, 4);
    assert_eq!(report.available_samples, 5);
    assert_eq!(report.unknown_label_samples, 1);
    // (0.01 + 0.01 + 0.81 + 0.81) / 4. The timeout is not p=0.
    assert!((report.brier_score.unwrap() - 0.41).abs() < 1e-12);
    assert_eq!(
        report.reliability.iter().map(|bin| bin.count).sum::<u32>(),
        4
    );
    assert_eq!(
        report
            .reliability
            .iter()
            .map(|bin| bin.observed_positives)
            .sum::<u32>(),
        2
    );
}

#[test]
fn unknown_truth_can_have_a_decision_but_cannot_have_a_supervised_score() {
    let samples = [sample(0, GroundTruth::Unknown, Some(0.1))];
    let report = evaluate(
        &samples,
        Thresholds::new(
            Probability::new(0.2).unwrap(),
            Probability::new(0.8).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(report.coverage.value(), Some(1.0));
    assert_eq!(report.unknown_rate.value(), Some(0.0));
    assert_eq!(report.scored_samples, 0);
    assert_eq!(report.brier_score, None);
    assert_eq!(report.false_allow_rate.value(), None);
    assert_eq!(report.false_deny_rate.value(), None);
    assert!(report.reliability.iter().all(|bin| bin.count == 0));
}
