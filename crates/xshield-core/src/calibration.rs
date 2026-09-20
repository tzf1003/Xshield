//! Bounded offline evaluation of a binary malicious-risk probability.
//!
//! This pure module uses only domain identifiers and the standard library. Its
//! allow/deny outcomes are hypothetical threshold classifications, never gateway
//! permissions, and cannot override deterministic rejection. Caller-approved
//! labels and probability semantics are inputs: vendor confidence and raw ordinal
//! Score values are not binary malicious probabilities. Numeric validation alone
//! does not establish those semantics or demonstrate that a model is calibrated.
//!
//! The caller owns tenant/site isolation, label approval, train/evaluation split,
//! fixed model/template revisions, evidence references, and durable audit of each
//! success or error. No IO, model invocation, policy publication or authorization
//! mutation occurs here. Success has reason `CALIBRATION_EVALUATED`; errors expose
//! stable reason codes. Work is bounded by [`MAX_SAMPLES`].

use crate::domain::ModelCallId;
use std::{collections::BTreeSet, fmt};

pub mod mapping;

/// Maximum samples accepted per evaluation; checked before any allocation.
pub const MAX_SAMPLES: usize = 10_000;
/// Number of fixed reliability intervals covering `[0, 1]`.
pub const RELIABILITY_BIN_COUNT: usize = 10;
const BIN_UPPER_BOUNDS: [f64; RELIABILITY_BIN_COUNT] =
    [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];

/// A finite binary malicious probability in `[0, 1]`, not vendor confidence.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Probability(f64);

impl Probability {
    /// Validates a caller-established malicious probability without side effects.
    ///
    /// # Errors
    /// Returns [`CalibrationError::InvalidProbability`] for nonfinite or out-of-range input.
    pub fn new(value: f64) -> Result<Self, CalibrationError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(CalibrationError::InvalidProbability);
        }
        Ok(Self(value))
    }

    /// Returns the validated probability, without allocation or side effects.
    #[must_use]
    pub const fn value(self) -> f64 {
        self.0
    }
}

/// Disjoint inclusive classification thresholds with an open abstention interval.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Thresholds {
    allow_below_or_equal: Probability,
    deny_above_or_equal: Probability,
}

impl Thresholds {
    /// Validates `allow_below_or_equal < deny_above_or_equal`, without effects.
    ///
    /// # Errors
    /// Returns [`CalibrationError::InvalidThresholds`] for equal or reversed bounds.
    pub fn new(
        allow_below_or_equal: Probability,
        deny_above_or_equal: Probability,
    ) -> Result<Self, CalibrationError> {
        if allow_below_or_equal.value() >= deny_above_or_equal.value() {
            return Err(CalibrationError::InvalidThresholds);
        }
        Ok(Self {
            allow_below_or_equal,
            deny_above_or_equal,
        })
    }

    /// Returns the inclusive hypothetical allow boundary.
    #[must_use]
    pub const fn allow_below_or_equal(self) -> Probability {
        self.allow_below_or_equal
    }

    /// Returns the inclusive hypothetical deny boundary.
    #[must_use]
    pub const fn deny_above_or_equal(self) -> Probability {
        self.deny_above_or_equal
    }
}

/// Caller-approved label; unknown human labels are independent of model abstention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroundTruth {
    /// Reviewed benign sample.
    Benign,
    /// Reviewed malicious sample.
    Malicious,
    /// Label remains unknown and is excluded from supervised quality metrics.
    Unknown,
}

/// Why a sample lacks a usable binary malicious probability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableReason {
    /// Model call failed.
    ModelFailed,
    /// Model call exceeded its deadline.
    ModelTimedOut,
    /// Model call was cancelled.
    ModelCancelled,
    /// No semantically applicable probability was supplied (including Noul).
    ProbabilityMissing,
}

/// A validated probability or an explicit unavailable terminal reason.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Signal {
    /// Caller-established binary malicious probability.
    Risk(Probability),
    /// Always abstains; never substitutes a zero probability.
    Unavailable(UnavailableReason),
}

/// One independently identified offline sample; identity must be unique per run.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    /// Existing model-call evidence reference; no raw model payload is needed.
    pub model_call_id: ModelCallId,
    /// Caller-approved ground truth, including explicit human uncertainty.
    pub ground_truth: GroundTruth,
    /// Risk probability semantics and provenance must be approved by the caller.
    pub signal: Signal,
}

/// Exact fraction with a separately inspectable denominator; zero means undefined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rate {
    /// Count of events in the numerator.
    pub numerator: u32,
    /// Population used for this metric, including abstention where documented.
    pub denominator: u32,
}

impl Rate {
    /// Computes the fraction, returning `None` for an empty population; no effects.
    #[must_use]
    pub fn value(self) -> Option<f64> {
        (self.denominator != 0).then(|| f64::from(self.numerator) / f64::from(self.denominator))
    }
}

/// Raw label-by-outcome counts; all nine cells sum to total samples.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConfusionCounts {
    /// Benign samples hypothetically allowed.
    pub benign_allow: u32,
    /// Benign samples hypothetically denied (false deny).
    pub benign_deny: u32,
    /// Benign samples abstained, including unavailable signals.
    pub benign_abstain: u32,
    /// Malicious samples hypothetically allowed (false allow).
    pub malicious_allow: u32,
    /// Malicious samples hypothetically denied.
    pub malicious_deny: u32,
    /// Malicious samples abstained, including unavailable signals.
    pub malicious_abstain: u32,
    /// Unknown-label samples hypothetically allowed.
    pub unknown_allow: u32,
    /// Unknown-label samples hypothetically denied.
    pub unknown_deny: u32,
    /// Unknown-label samples abstained, including unavailable signals.
    pub unknown_abstain: u32,
}

/// Missing-signal counts by terminal reason; sum equals `missing_samples`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UnavailableCounts {
    /// Failed calls.
    pub model_failed: u32,
    /// Timed-out calls.
    pub model_timed_out: u32,
    /// Cancelled calls.
    pub model_cancelled: u32,
    /// Calls without an applicable probability.
    pub probability_missing: u32,
}

/// Reliability of known-label probability samples in one fixed interval.
///
/// Indices 0..8 represent `[i/10, (i+1)/10)`; index 9 represents `[0.9, 1]`.
/// Boundaries use the nearest `f64` representations of decimal tenths. Unknown
/// labels and unavailable signals are excluded. Empty bins keep mean `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ReliabilityBin {
    /// Number of scored samples in this interval.
    pub count: u32,
    /// Malicious labels in this interval; divide by count for observed frequency.
    pub observed_positives: u32,
    /// Arithmetic mean risk probability, absent exactly when count is zero.
    pub mean_probability: Option<f64>,
}

/// Offline descriptive results, not an authorization or a calibrated-model claim.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    /// Exact accepted input size (1 through 10,000).
    pub total_samples: u32,
    /// Samples with a probability, including unknown human labels.
    pub available_samples: u32,
    /// Samples with unavailable signals; included in abstention cells.
    pub missing_samples: u32,
    /// Samples with unknown human labels, independently of signal availability.
    pub unknown_label_samples: u32,
    /// Known-label samples with a probability; denominator for Brier and bin totals.
    pub scored_samples: u32,
    /// Raw label/outcome matrix.
    pub counts: ConfusionCounts,
    /// Explicit unavailable terminal reasons.
    pub unavailable_counts: UnavailableCounts,
    /// Malicious allow / all known malicious samples (including abstained).
    pub false_allow_rate: Rate,
    /// Benign deny / all known benign samples (including abstained).
    pub false_deny_rate: Rate,
    /// All allow and deny outcomes / all samples, including unknown labels.
    pub coverage: Rate,
    /// All abstention outcomes / all samples; distinct from unknown human labels.
    pub unknown_rate: Rate,
    /// Fixed reliability intervals, containing only known-label probability samples.
    pub reliability: [ReliabilityBin; RELIABILITY_BIN_COUNT],
    /// Mean `(probability - label)^2` over `scored_samples`; absent when zero.
    pub brier_score: Option<f64>,
}

impl Report {
    /// Returns the stable successful evaluation reason for caller-owned audit.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        "CALIBRATION_EVALUATED"
    }
}

/// Closed validation errors, with no raw payloads or identifiers in messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationError {
    /// Probability was nonfinite or outside `[0, 1]`.
    InvalidProbability,
    /// Allow boundary was greater than or equal to deny boundary.
    InvalidThresholds,
    /// Evaluation had no samples.
    EmptySamples,
    /// Evaluation exceeded the hard sample bound.
    TooManySamples,
    /// A model-call evidence reference appeared more than once.
    DuplicateModelCallId,
}

impl CalibrationError {
    /// Returns a stable machine-readable reason for caller-owned durable audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidProbability => "CALIBRATION_PROBABILITY_INVALID",
            Self::InvalidThresholds => "CALIBRATION_THRESHOLDS_INVALID",
            Self::EmptySamples => "CALIBRATION_SAMPLES_EMPTY",
            Self::TooManySamples => "CALIBRATION_SAMPLE_LIMIT_EXCEEDED",
            Self::DuplicateModelCallId => "CALIBRATION_MODEL_CALL_DUPLICATE",
        }
    }
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}
impl std::error::Error for CalibrationError {}

#[derive(Clone, Copy)]
enum Outcome {
    Allow,
    Deny,
    Abstain,
}

/// Evaluates a fixed hypothetical threshold policy with no external effects.
///
/// Input order is preserved for floating-point summation. Work is O(n log n),
/// using at most n borrowed IDs in a `BTreeSet` and ten reliability accumulators.
/// Missing signals always abstain. Unknown labels still count for coverage but
/// never for error rates, Brier or reliability. Callers must retain the approved
/// dataset, revisions, thresholds and this terminal result in durable audit.
///
/// # Errors
/// Returns [`CalibrationError::EmptySamples`], [`CalibrationError::TooManySamples`]
/// or [`CalibrationError::DuplicateModelCallId`]; no partial report is returned.
///
/// # Example
/// ```
/// use xshield_core::calibration::{Probability, Thresholds, evaluate, CalibrationError};
/// let thresholds = Thresholds::new(Probability::new(0.2)?, Probability::new(0.8)?)?;
/// assert_eq!(evaluate(&[], thresholds), Err(CalibrationError::EmptySamples));
/// # Ok::<(), CalibrationError>(())
/// ```
pub fn evaluate(samples: &[Sample], thresholds: Thresholds) -> Result<Report, CalibrationError> {
    if samples.is_empty() {
        return Err(CalibrationError::EmptySamples);
    }
    if samples.len() > MAX_SAMPLES {
        return Err(CalibrationError::TooManySamples);
    }
    let mut ids = BTreeSet::new();
    let mut counts = ConfusionCounts::default();
    let mut unavailable = UnavailableCounts::default();
    let mut bins = [ReliabilityBin::default(); RELIABILITY_BIN_COUNT];
    let mut probability_sums = [0.0; RELIABILITY_BIN_COUNT];
    let (mut total, mut available, mut scored, mut unknown_labels) = (0, 0, 0, 0);
    let mut squared_error = 0.0;
    for sample in samples {
        if !ids.insert(&sample.model_call_id) {
            return Err(CalibrationError::DuplicateModelCallId);
        }
        total += 1;
        unknown_labels += u32::from(sample.ground_truth == GroundTruth::Unknown);
        let outcome = match sample.signal {
            Signal::Risk(probability) => {
                available += 1;
                if sample.ground_truth != GroundTruth::Unknown {
                    scored += 1;
                    let positive = u32::from(sample.ground_truth == GroundTruth::Malicious);
                    squared_error += (probability.value() - f64::from(positive)).powi(2);
                    // Comparisons avoid rounded multiplication moving a value just
                    // below a decimal edge into the next bin.
                    let index = BIN_UPPER_BOUNDS
                        .iter()
                        .take(9)
                        .filter(|upper| probability.value() >= **upper)
                        .count();
                    bins[index].count += 1;
                    bins[index].observed_positives += positive;
                    probability_sums[index] += probability.value();
                }
                if probability.value() <= thresholds.allow_below_or_equal.value() {
                    Outcome::Allow
                } else if probability.value() >= thresholds.deny_above_or_equal.value() {
                    Outcome::Deny
                } else {
                    Outcome::Abstain
                }
            }
            Signal::Unavailable(reason) => {
                match reason {
                    UnavailableReason::ModelFailed => unavailable.model_failed += 1,
                    UnavailableReason::ModelTimedOut => unavailable.model_timed_out += 1,
                    UnavailableReason::ModelCancelled => unavailable.model_cancelled += 1,
                    UnavailableReason::ProbabilityMissing => unavailable.probability_missing += 1,
                }
                Outcome::Abstain
            }
        };
        record_outcome(&mut counts, sample.ground_truth, outcome);
    }
    for (bin, sum) in bins.iter_mut().zip(probability_sums) {
        bin.mean_probability = (bin.count != 0).then(|| sum / f64::from(bin.count));
    }
    Ok(build_report(
        total,
        available,
        scored,
        unknown_labels,
        counts,
        unavailable,
        bins,
        squared_error,
    ))
}

fn record_outcome(counts: &mut ConfusionCounts, label: GroundTruth, outcome: Outcome) {
    let cell = match (label, outcome) {
        (GroundTruth::Benign, Outcome::Allow) => &mut counts.benign_allow,
        (GroundTruth::Benign, Outcome::Deny) => &mut counts.benign_deny,
        (GroundTruth::Benign, Outcome::Abstain) => &mut counts.benign_abstain,
        (GroundTruth::Malicious, Outcome::Allow) => &mut counts.malicious_allow,
        (GroundTruth::Malicious, Outcome::Deny) => &mut counts.malicious_deny,
        (GroundTruth::Malicious, Outcome::Abstain) => &mut counts.malicious_abstain,
        (GroundTruth::Unknown, Outcome::Allow) => &mut counts.unknown_allow,
        (GroundTruth::Unknown, Outcome::Deny) => &mut counts.unknown_deny,
        (GroundTruth::Unknown, Outcome::Abstain) => &mut counts.unknown_abstain,
    };
    *cell += 1;
}

#[allow(clippy::too_many_arguments)] // Fixed aggregate values, no external resources or configuration.
fn build_report(
    total: u32,
    available: u32,
    scored: u32,
    unknown_labels: u32,
    counts: ConfusionCounts,
    unavailable_counts: UnavailableCounts,
    reliability: [ReliabilityBin; RELIABILITY_BIN_COUNT],
    squared_error: f64,
) -> Report {
    let abstained = counts.benign_abstain + counts.malicious_abstain + counts.unknown_abstain;
    Report {
        total_samples: total,
        available_samples: available,
        missing_samples: total - available,
        scored_samples: scored,
        unknown_label_samples: unknown_labels,
        false_allow_rate: Rate {
            numerator: counts.malicious_allow,
            denominator: counts.malicious_allow + counts.malicious_deny + counts.malicious_abstain,
        },
        false_deny_rate: Rate {
            numerator: counts.benign_deny,
            denominator: counts.benign_allow + counts.benign_deny + counts.benign_abstain,
        },
        coverage: Rate {
            numerator: total - abstained,
            denominator: total,
        },
        unknown_rate: Rate {
            numerator: abstained,
            denominator: total,
        },
        counts,
        unavailable_counts,
        reliability,
        brier_score: (scored != 0).then(|| squared_error / f64::from(scored)),
    }
}

#[cfg(test)]
#[path = "calibration/tests.rs"]
mod tests;
