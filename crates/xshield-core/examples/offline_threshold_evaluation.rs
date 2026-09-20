//! Synthetic, side-effect-free demonstration of threshold metric denominators.
//!
//! This executable makes no provider call and publishes no policy or report.

use xshield_core::{
    calibration::{
        GroundTruth, Probability, Sample, Signal, Thresholds, UnavailableReason, evaluate,
    },
    domain::ModelCallId,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let samples = [
        (GroundTruth::Benign, Signal::Risk(Probability::new(0.1)?)),
        (GroundTruth::Malicious, Signal::Risk(Probability::new(0.9)?)),
        (GroundTruth::Malicious, Signal::Risk(Probability::new(0.1)?)),
        (GroundTruth::Benign, Signal::Risk(Probability::new(0.9)?)),
        (
            GroundTruth::Malicious,
            Signal::Unavailable(UnavailableReason::ModelTimedOut),
        ),
        (GroundTruth::Unknown, Signal::Risk(Probability::new(0.5)?)),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (ground_truth, signal))| {
        Ok(Sample {
            model_call_id: ModelCallId::parse(format!("mdl_018f2a3b-4c5d-7000-8000-{index:012x}"))?,
            ground_truth,
            signal,
        })
    })
    .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let thresholds = Thresholds::new(Probability::new(0.2)?, Probability::new(0.8)?)?;
    let report = evaluate(&samples, thresholds)?;
    println!(
        "synthetic_example=true samples={} scored={} missing={} unknown_labels={}",
        report.total_samples,
        report.scored_samples,
        report.missing_samples,
        report.unknown_label_samples
    );
    for (name, rate) in [
        ("false_allow", report.false_allow_rate),
        ("false_deny", report.false_deny_rate),
        ("coverage", report.coverage),
        ("unknown", report.unknown_rate),
    ] {
        println!(
            "{name}={}/{} value={:?}",
            rate.numerator,
            rate.denominator,
            rate.value()
        );
    }
    println!("brier_score={:?}", report.brier_score);
    Ok(())
}
