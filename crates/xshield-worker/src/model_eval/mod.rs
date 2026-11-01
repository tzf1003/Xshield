//! Closed model lifecycle event shape shared by the journal parser and the
//! analytical index.
//!
//! The offline, operator-approved Jev evaluation runner this module used to
//! contain (CLI, provider transport, wire types, evidence capture, caching)
//! was deleted with the v3 gateway: Jev is now called synchronously in the
//! request path by `xshield-judge` (see docs/02, docs/05 §5.2). Only the
//! closed event shape below remains, because the publisher in [`crate`]
//! still parses and validates historical `model.*` journal events for the
//! analytical index.

use serde::{Deserialize, Deserializer, Serialize};
use xshield_core::domain::ModelCallId;

/// Closed model lifecycle metadata. Kept typed at both journal boundaries.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelEvent {
    pub(crate) model_call_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cache_source_model_call_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_non_null_option")]
    pub(crate) provider: Option<String>,
    #[serde(default, deserialize_with = "deserialize_non_null_option")]
    pub(crate) provider_model_id: Option<String>,
    pub(crate) model_revision: String,
    pub(crate) prompt_revision: String,
    pub(crate) question_type: String,
    pub(crate) status: String,
    pub(crate) reason_code: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) confidence: Option<f64>,
    pub(crate) confidence_status: String,
    pub(crate) duration_us: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) input_artifact_id: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) output_artifact_id: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) call_artifact_id: Option<String>,
}

fn deserialize_non_null_option<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("null is not an absent provider field"))
}

impl ModelEvent {
    pub(crate) fn parse_query_event(
        payload: &str,
        event_type: &str,
    ) -> Result<Self, crate::PublishError> {
        let event: Self = serde_json::from_str(payload)?;
        event.clone().validate(event_type)?;
        Ok(event)
    }

    pub(super) fn validate_envelope(event: &crate::WireEvent) -> Result<(), crate::PublishError> {
        let payload: Self = serde_json::from_str(event.payload.get())?;
        if event.request_id.is_none()
            || [
                &payload.input_artifact_id,
                &payload.output_artifact_id,
                &payload.call_artifact_id,
            ]
            .into_iter()
            .flatten()
            .any(|id| !event.evidence_refs.contains(id))
        {
            return Err(crate::PublishError::InvalidEvent);
        }
        Ok(())
    }

    pub(super) fn validate(
        self,
        event_type: &str,
    ) -> Result<crate::PayloadSummary, crate::PublishError> {
        use crate::PublishError::InvalidEvent;
        ModelCallId::parse(&self.model_call_id).map_err(|_| InvalidEvent)?;
        match (&self.provider, &self.provider_model_id) {
            (None, None) => {}
            (Some(provider), Some(provider_model_id))
                if crate::valid_name(provider)
                    && ((provider == "typesafe" && provider_model_id == "jev-1.13.0")
                        || (provider == "vercel_ai_gateway"
                            && provider_model_id == "typesafe-ai/jev")) => {}
            _ => return Err(InvalidEvent),
        }
        let outcome = match (event_type, self.status.as_str()) {
            ("model.started", "started") | ("model.requested" | "model.cache_hit", "requested") => {
                "UNKNOWN"
            }
            ("model.responded", "success") => "PASS",
            ("model.timeout", "timeout") | ("model.failed", "error") => "ERROR",
            ("model.cancelled", "cancelled") => "CANCELLED",
            _ => return Err(InvalidEvent),
        };
        if !crate::valid_name(&self.model_revision)
            || !crate::valid_name(&self.prompt_revision)
            || !crate::valid_name(&self.reason_code)
            || !matches!(self.question_type.as_str(), "choice" | "score" | "noul")
            || (event_type == "model.cache_hit"
                && (self.reason_code != "MODEL_CACHE_HIT"
                    || self.cache_source_model_call_id.is_none()))
            || (event_type != "model.cache_hit" && self.cache_source_model_call_id.is_some())
            || !crate::valid_confidence("model", outcome, self.confidence, &self.confidence_status)
            || (self.question_type == "noul" && self.confidence_status != "not_applicable")
            || (self.status != "success" && self.confidence.is_some())
            || (matches!(self.status.as_str(), "requested" | "success")
                && self.input_artifact_id.is_none())
            || (self.status == "success"
                && (self.output_artifact_id.is_none() || self.call_artifact_id.is_none()))
        {
            return Err(InvalidEvent);
        }
        for id in [
            &self.input_artifact_id,
            &self.output_artifact_id,
            &self.call_artifact_id,
        ]
        .into_iter()
        .flatten()
        {
            xshield_core::domain::ArtifactId::parse(id).map_err(|_| InvalidEvent)?;
        }
        if let Some(source) = &self.cache_source_model_call_id {
            ModelCallId::parse(source).map_err(|_| InvalidEvent)?;
        }
        Ok(crate::PayloadSummary {
            stage: "model_eval".to_owned(),
            outcome: outcome.to_owned(),
            reason_code: self.reason_code,
            proof_kind: "model".to_owned(),
            confidence: self.confidence,
            confidence_status: self.confidence_status,
            model_revision: self.model_revision,
            model_call_id: self.model_call_id,
            duration_us: self.duration_us,
            ..crate::PayloadSummary::default()
        })
    }
}

#[cfg(test)]
mod tests;
