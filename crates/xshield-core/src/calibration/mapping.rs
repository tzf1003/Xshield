//! Approved conversion of complete model distributions into offline risk signals.
//!
//! Callers establish approval, task semantics, evidence provenance and durable
//! audit. This pure module validates bounded names and mass, retains unknown
//! mass, and exposes terminal reason codes. It performs no IO or authorization.

use super::{Probability, Signal, UnavailableReason};
use crate::domain::{FieldName, MappingRevision};
use std::{collections::BTreeMap, fmt};

/// Maximum approved outcomes and distribution entries.
pub const MAX_MAPPING_OUTCOMES: usize = 32;
/// Absolute serialization tolerance for the complete distribution's mass.
pub const DISTRIBUTION_SUM_TOLERANCE: f64 = 1e-6;
/// Maximum arithmetic excess above one accepted for an individual class sum.
const CLASS_ROUNDOFF_TOLERANCE: f64 = 32.0 * f64::EPSILON;

/// Caller-approved semantic meaning of an outcome, independent of its ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskClass {
    /// Evidence supporting benign behavior.
    Benign,
    /// Evidence supporting malicious behavior.
    Malicious,
    /// Unresolved behavior; any positive mass requires abstention.
    Unknown,
}

/// Immutable, revision-bound assignment of every outcome to a risk class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedRiskMapping {
    revision: MappingRevision,
    assignments: BTreeMap<String, RiskClass>,
}

impl ApprovedRiskMapping {
    /// Validates 2–32 unique ASCII scoped names and a scoped revision (1–128
    /// bytes; letters, digits, `_`, `-`, `.`). Requires benign and malicious
    /// classes. Approval and task-specific candidate requirements belong to the
    /// caller. Allocates at most 32 entries and performs no external effects.
    ///
    /// # Errors
    /// Returns a stable [`MappingError`] for invalid names, count, duplicates,
    /// or absent required classes. Callers durably audit success or error.
    pub fn new(
        revision: String,
        assignments: Vec<(String, RiskClass)>,
    ) -> Result<Self, MappingError> {
        if !(2..=MAX_MAPPING_OUTCOMES).contains(&assignments.len()) {
            return Err(MappingError::InvalidOutcomeCount);
        }
        let revision =
            MappingRevision::parse(revision).map_err(|_| MappingError::InvalidRevision)?;
        let mut approved = BTreeMap::new();
        for (key, class) in assignments {
            let key = FieldName::parse(key).map_err(|_| MappingError::InvalidOutcomeName)?;
            if approved.insert(key.as_str().to_owned(), class).is_some() {
                return Err(MappingError::DuplicateOutcome);
            }
        }
        if !approved.values().any(|class| *class == RiskClass::Benign)
            || !approved
                .values()
                .any(|class| *class == RiskClass::Malicious)
        {
            return Err(MappingError::MissingRequiredClass);
        }
        Ok(Self {
            revision,
            assignments: approved,
        })
    }

    /// Returns the approved revision for evidence and caller-owned audit.
    #[must_use]
    pub fn revision(&self) -> &str {
        self.revision.as_str()
    }

    /// Projects the complete reviewed distribution using exact outcome keys.
    ///
    /// Sum tolerance is [`DISTRIBUTION_SUM_TOLERANCE`]. Class masses remain raw
    /// sums; none are renormalized. An individual sum above one is accepted only
    /// within `32 * f64::EPSILON`, with that arithmetic excess clamped solely in
    /// the binary signal. Any positive unknown mass forces abstention. Summation
    /// follows canonical key order, so wire order does not affect the result.
    /// Work and temporary memory are bounded by 32 entries; no IO occurs.
    ///
    /// # Errors
    /// Rejects oversized, duplicate, missing or extra keys, invalid total mass,
    /// or class mass above the arithmetic allowance. Caller retains the mapping
    /// revision, source evidence, result and reason in durable audit.
    pub fn project(
        &self,
        distribution: &[(String, Probability)],
    ) -> Result<MappedRisk, MappingError> {
        if distribution.len() > MAX_MAPPING_OUTCOMES {
            return Err(MappingError::InvalidOutcomeCount);
        }
        let mut probabilities = BTreeMap::new();
        for (key, probability) in distribution {
            if !self.assignments.contains_key(key) {
                return Err(MappingError::ExtraOutcome);
            }
            if probabilities.insert(key, probability.value()).is_some() {
                return Err(MappingError::DuplicateOutcome);
            }
        }
        if probabilities.len() != self.assignments.len() {
            return Err(MappingError::MissingOutcome);
        }
        let (mut benign, mut malicious, mut unknown) = (0.0, 0.0, 0.0);
        let mut total = 0.0;
        for (key, class) in &self.assignments {
            let mass = probabilities.get(key).ok_or(MappingError::MissingOutcome)?;
            total += mass;
            match class {
                RiskClass::Benign => benign += mass,
                RiskClass::Malicious => malicious += mass,
                RiskClass::Unknown => unknown += mass,
            }
        }
        if (total - 1.0).abs() > DISTRIBUTION_SUM_TOLERANCE {
            return Err(MappingError::InvalidTotalMass);
        }
        if [benign, malicious, unknown]
            .iter()
            .any(|mass| *mass > 1.0 + CLASS_ROUNDOFF_TOLERANCE)
        {
            return Err(MappingError::InvalidClassMass);
        }
        let signal = if unknown > 0.0 {
            Signal::Unavailable(UnavailableReason::ProbabilityMissing)
        } else {
            // Only summation roundoff can reach this clamp; raw mass is retained.
            Signal::Risk(
                Probability::new(malicious.min(1.0)).map_err(|_| MappingError::InvalidClassMass)?,
            )
        };
        Ok(MappedRisk {
            revision: self.revision.clone(),
            benign,
            malicious,
            unknown,
            signal,
        })
    }
}

/// Terminal projection retaining all class mass and the approved revision.
#[derive(Clone, Debug, PartialEq)]
pub struct MappedRisk {
    revision: MappingRevision,
    benign: f64,
    malicious: f64,
    unknown: f64,
    signal: Signal,
}

impl MappedRisk {
    /// Returns the exact mapping revision for audit binding.
    #[must_use]
    pub fn revision(&self) -> &str {
        self.revision.as_str()
    }
    /// Returns the original benign sum, including accepted arithmetic roundoff.
    #[must_use]
    pub const fn benign_probability(&self) -> f64 {
        self.benign
    }
    /// Returns the original malicious sum, including accepted arithmetic roundoff.
    #[must_use]
    pub const fn malicious_probability(&self) -> f64 {
        self.malicious
    }
    /// Returns the original unknown sum; positive mass always abstains.
    #[must_use]
    pub const fn unknown_probability(&self) -> f64 {
        self.unknown
    }
    /// Returns the offline calibration signal, with no authorization effects.
    #[must_use]
    pub const fn signal(&self) -> Signal {
        self.signal
    }
    /// Returns a stable terminal reason for caller-owned audit.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        if self.unknown > 0.0 {
            "RISK_MAPPING_ABSTAINED"
        } else {
            "RISK_MAPPING_PROJECTED"
        }
    }
}

/// Closed input failures carrying stable codes and no model payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingError {
    /// Revision violates scoped-name syntax.
    InvalidRevision,
    /// Outcome count is outside the bounded contract.
    InvalidOutcomeCount,
    /// Approved outcome violates scoped-name syntax.
    InvalidOutcomeName,
    /// An outcome appears more than once.
    DuplicateOutcome,
    /// Approval omits benign or malicious semantics.
    MissingRequiredClass,
    /// Distribution omits an approved outcome.
    MissingOutcome,
    /// Distribution contains an unapproved outcome.
    ExtraOutcome,
    /// Total mass differs from one beyond serialization tolerance.
    InvalidTotalMass,
    /// A class exceeds one beyond arithmetic roundoff.
    InvalidClassMass,
}

impl MappingError {
    /// Returns a stable code for caller-owned durable terminal audit.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidRevision => "RISK_MAPPING_REVISION_INVALID",
            Self::InvalidOutcomeCount => "RISK_MAPPING_OUTCOME_COUNT_INVALID",
            Self::InvalidOutcomeName => "RISK_MAPPING_OUTCOME_NAME_INVALID",
            Self::DuplicateOutcome => "RISK_MAPPING_OUTCOME_DUPLICATE",
            Self::MissingRequiredClass => "RISK_MAPPING_REQUIRED_CLASS_MISSING",
            Self::MissingOutcome => "RISK_MAPPING_OUTCOME_MISSING",
            Self::ExtraOutcome => "RISK_MAPPING_OUTCOME_EXTRA",
            Self::InvalidTotalMass => "RISK_MAPPING_TOTAL_MASS_INVALID",
            Self::InvalidClassMass => "RISK_MAPPING_CLASS_MASS_INVALID",
        }
    }
}
impl fmt::Display for MappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}
impl std::error::Error for MappingError {}

#[cfg(test)]
#[path = "mapping_tests.rs"]
mod tests;
