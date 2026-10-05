//! Strict browser sensor observation contract.

use serde::Deserialize;
use uuid::{Uuid, Version};
use xshield_core::{domain::RequestId, provenance::BuildFingerprint};

/// Maximum accepted serialized observation size.
pub const MAX_SENSOR_OBSERVATION_BYTES: usize = 16 * 1024;
const MAX_CLIENT_TEXT_BYTES: usize = 256;
const MAX_CLIENT_EVENT_SEQUENCE: u32 = 64;
const MAX_BATCH_EVENTS: usize = 16;

/// One bounded HTTPS observation batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorObservationBatch {
    observations: Vec<SensorObservation>,
}

/// Validated client-claimed sensor observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorObservation {
    sensor_version: String,
    build_ref: String,
    page_handle: String,
    navigation_id: String,
    action_hint: Option<String>,
    client_request_id: Option<RequestId>,
    client_event_seq: u32,
    visibility: SensorVisibility,
    event_type: SensorEventType,
    callsite_fingerprint: Option<String>,
}

/// Browser visibility state carried by an observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorVisibility {
    /// The page was visible when the event was created.
    Visible,
    /// The page was hidden when the event was created.
    Hidden,
}

impl SensorVisibility {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::Hidden => "hidden",
        }
    }
}

/// Supported observational browser lifecycle event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorEventType {
    /// The sensor initialized for one page navigation.
    PageReady,
    /// The active-page liveness timer fired.
    Heartbeat,
    /// Browser visibility changed.
    Visibility,
}

impl SensorEventType {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PageReady => "PAGE_READY",
            Self::Heartbeat => "HEARTBEAT",
            Self::Visibility => "VISIBILITY",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorObservationDto {
    sensor_version: String,
    build_ref: String,
    page_handle: String,
    navigation_id: String,
    action_hint: Option<String>,
    client_request_id: Option<String>,
    client_event_seq: u32,
    visibility: String,
    event_type: String,
    callsite_fingerprint: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorObservationBatchDto {
    events: Vec<SensorObservationDto>,
}

/// Sensor observation validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSensorObservation;

impl SensorObservation {
    fn from_dto(
        dto: SensorObservationDto,
        accepted_versions: &[&str],
        expected_build_ref: &str,
    ) -> Result<Self, InvalidSensorObservation> {
        if !accepted_versions.contains(&dto.sensor_version.as_str())
            || dto.build_ref != expected_build_ref
            || !prefixed_v7(&dto.page_handle, "pgh_")
            || !prefixed_v7(&dto.navigation_id, "nav_")
            || !optional_client_text(dto.action_hint.as_deref())
        {
            return Err(InvalidSensorObservation);
        }
        let client_request_id = dto
            .client_request_id
            .map(RequestId::parse)
            .transpose()
            .map_err(|_| InvalidSensorObservation)?;
        let callsite_fingerprint = dto
            .callsite_fingerprint
            .map(|value| {
                BuildFingerprint::parse(&value)
                    .map(|_| value)
                    .map_err(|_| InvalidSensorObservation)
            })
            .transpose()?;
        let visibility = match dto.visibility.as_str() {
            "visible" => SensorVisibility::Visible,
            "hidden" => SensorVisibility::Hidden,
            _ => return Err(InvalidSensorObservation),
        };
        let event_type = match dto.event_type.as_str() {
            "PAGE_READY" => SensorEventType::PageReady,
            "HEARTBEAT" => SensorEventType::Heartbeat,
            "VISIBILITY" => SensorEventType::Visibility,
            _ => return Err(InvalidSensorObservation),
        };
        if !(1..=MAX_CLIENT_EVENT_SEQUENCE).contains(&dto.client_event_seq)
            || matches!(event_type, SensorEventType::PageReady) != (dto.client_event_seq == 1)
        {
            return Err(InvalidSensorObservation);
        }
        Ok(Self {
            sensor_version: dto.sensor_version,
            build_ref: dto.build_ref,
            page_handle: dto.page_handle,
            navigation_id: dto.navigation_id,
            action_hint: dto.action_hint,
            client_request_id,
            client_event_seq: dto.client_event_seq,
            visibility,
            event_type,
            callsite_fingerprint,
        })
    }

    /// Returns the configured page build reference.
    #[must_use]
    pub fn build_ref(&self) -> &str {
        &self.build_ref
    }

    /// Returns the client page handle.
    #[must_use]
    pub fn page_handle(&self) -> &str {
        &self.page_handle
    }

    /// Returns the client navigation identifier.
    #[must_use]
    pub fn navigation_id(&self) -> &str {
        &self.navigation_id
    }

    /// Returns the non-authoritative client action hint.
    #[must_use]
    pub fn action_hint(&self) -> Option<&str> {
        self.action_hint.as_deref()
    }

    /// Returns the optional client-associated request identifier.
    #[must_use]
    pub const fn client_request_id(&self) -> Option<&RequestId> {
        self.client_request_id.as_ref()
    }

    /// Returns the client sequence within this page.
    #[must_use]
    pub const fn client_event_seq(&self) -> u32 {
        self.client_event_seq
    }

    /// Returns browser visibility at event creation.
    #[must_use]
    pub const fn visibility(&self) -> SensorVisibility {
        self.visibility
    }

    /// Returns the validated lifecycle event type.
    #[must_use]
    pub const fn event_type(&self) -> SensorEventType {
        self.event_type
    }

    /// Returns the optional client callsite fingerprint.
    #[must_use]
    pub fn callsite_fingerprint(&self) -> Option<&str> {
        self.callsite_fingerprint.as_deref()
    }
}

impl SensorObservationBatch {
    /// Parses one complete bounded JSON batch against the configured build.
    ///
    /// `accepted_versions` lists every sensor version whose assets the edge
    /// still serves; one batch must use a single version.
    ///
    /// # Errors
    /// Returns [`InvalidSensorObservation`] for invalid JSON, unknown fields,
    /// unsupported or mixed versions, malformed identifiers, or incoherent
    /// sequencing.
    pub fn from_json(
        bytes: &[u8],
        accepted_versions: &[&str],
        expected_build_ref: &str,
    ) -> Result<Self, InvalidSensorObservation> {
        if bytes.is_empty() || bytes.len() > MAX_SENSOR_OBSERVATION_BYTES {
            return Err(InvalidSensorObservation);
        }
        let dto: SensorObservationBatchDto =
            serde_json::from_slice(bytes).map_err(|_| InvalidSensorObservation)?;
        if !(1..=MAX_BATCH_EVENTS).contains(&dto.events.len()) {
            return Err(InvalidSensorObservation);
        }
        let observations = dto
            .events
            .into_iter()
            .map(|event| SensorObservation::from_dto(event, accepted_versions, expected_build_ref))
            .collect::<Result<Vec<_>, _>>()?;
        let first = observations.first().ok_or(InvalidSensorObservation)?;
        if observations.iter().enumerate().any(|(index, observation)| {
            observation.sensor_version != first.sensor_version
                || observation.build_ref != first.build_ref
                || observation.page_handle != first.page_handle
                || observation.navigation_id != first.navigation_id
                || usize::try_from(observation.client_event_seq)
                    .ok()
                    .zip(usize::try_from(first.client_event_seq).ok())
                    .is_none_or(|(sequence, start)| sequence != start + index)
        }) {
            return Err(InvalidSensorObservation);
        }
        Ok(Self { observations })
    }

    /// Returns observations in client sequence order.
    #[must_use]
    pub fn observations(&self) -> &[SensorObservation] {
        &self.observations
    }
}

fn prefixed_v7(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|value| Uuid::parse_str(value).ok())
        .is_some_and(|value| value.get_version() == Some(Version::SortRand))
}

/// A hint is client text: bounded printable ASCII that is never an action
/// reference. References must not enter the journal or the analytical index, and
/// the audit publisher refuses such a record, so a hostile client could
/// otherwise stall publication by sending one. The real sensor never sends a hint.
fn optional_client_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_CLIENT_TEXT_BYTES
            && value.bytes().all(|byte| byte.is_ascii_graphic())
            && !value.contains("action.")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn event(event_type: &str, sequence: u32) -> Vec<u8> {
        serde_json::json!({"events": [{
            "sensor_version": "1.0.0",
            "build_ref": BUILD,
            "page_handle": "pgh_018f2a3b-4c5d-7000-8000-000000000101",
            "navigation_id": "nav_018f2a3b-4c5d-7000-8000-000000000102",
            "action_hint": null,
            "client_request_id": null,
            "client_event_seq": sequence,
            "visibility": "visible",
            "event_type": event_type,
            "callsite_fingerprint": null
        }]})
        .to_string()
        .into_bytes()
    }

    #[test]
    fn accepts_only_exact_bounded_observations() {
        let accepted = &crate::ACCEPTED_SENSOR_VERSIONS[..];
        let ready =
            SensorObservationBatch::from_json(&event("PAGE_READY", 1), accepted, BUILD).unwrap();
        assert_eq!(
            ready.observations()[0].event_type(),
            SensorEventType::PageReady
        );
        assert!(
            SensorObservationBatch::from_json(&event("PAGE_READY", 2), accepted, BUILD).is_err()
        );
        assert!(
            SensorObservationBatch::from_json(&event("HEARTBEAT", 1), accepted, BUILD).is_err()
        );
        assert!(SensorObservationBatch::from_json(&event("UNKNOWN", 2), accepted, BUILD).is_err());
        assert!(
            SensorObservationBatch::from_json(&event("HEARTBEAT", 2), &["1.0.1"], BUILD).is_err()
        );
    }

    #[test]
    fn a_hint_is_bounded_printable_text_and_never_an_action_reference() {
        let accepted = &crate::ACCEPTED_SENSOR_VERSIONS[..];
        let with_hint = |hint: serde_json::Value| {
            let mut batch: serde_json::Value =
                serde_json::from_slice(&event("PAGE_READY", 1)).unwrap();
            batch["events"][0]["action_hint"] = hint;
            SensorObservationBatch::from_json(batch.to_string().as_bytes(), accepted, BUILD)
        };
        assert!(with_hint("orders.submit".into()).is_ok());
        assert!(with_hint("h".repeat(MAX_CLIENT_TEXT_BYTES).into()).is_ok());
        let reference = format!("action.{}", "a".repeat(64));
        for hint in [
            reference.clone(),
            format!("try-{reference}"),
            String::new(),
            "two words".to_owned(),
            "h".repeat(MAX_CLIENT_TEXT_BYTES + 1),
            "caf\u{e9}".to_owned(),
        ] {
            assert!(with_hint(hint.clone().into()).is_err(), "{hint}");
        }
    }

    #[test]
    fn accepts_every_served_version_but_never_a_mixed_batch() {
        let accepted = &crate::ACCEPTED_SENSOR_VERSIONS[..];
        let mut batch: serde_json::Value = serde_json::from_slice(&event("PAGE_READY", 1)).unwrap();
        for version in crate::ACCEPTED_SENSOR_VERSIONS {
            batch["events"][0]["sensor_version"] = version.into();
            assert!(
                SensorObservationBatch::from_json(batch.to_string().as_bytes(), accepted, BUILD)
                    .is_ok()
            );
        }
        let mut second = batch["events"][0].clone();
        second["event_type"] = "HEARTBEAT".into();
        second["client_event_seq"] = 2.into();
        second["sensor_version"] = crate::LEGACY_SENSOR_VERSION.into();
        batch["events"][0]["sensor_version"] = crate::SENSOR_VERSION.into();
        batch["events"].as_array_mut().unwrap().push(second);
        assert!(
            SensorObservationBatch::from_json(batch.to_string().as_bytes(), accepted, BUILD)
                .is_err()
        );
    }
}
