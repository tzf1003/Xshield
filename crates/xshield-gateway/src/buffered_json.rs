use bytes::Bytes;
use openssl::rand::rand_bytes;
use pingora::http::ResponseHeader;
use std::{collections::BTreeSet, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use xshield_core::audit::ReasonCode;
use xshield_gateway::response_grant::{ResponseGrantError, validate_strict_json};
use xshield_gateway::{BufferedResponsePolicy, sensor_html::SensorHtmlRule};

pub(crate) struct BufferedResponse {
    bytes: Vec<u8>,
    limit: usize,
    kind: BufferedResponseKind,
    _permit: OwnedSemaphorePermit,
}

pub(crate) struct BufferedEntity {
    pub(crate) body: Bytes,
    pub(crate) sensor_html: Option<SensorHtmlTransformation>,
}

pub(crate) struct SensorHtmlTransformation {
    pub(crate) adapter_revision: String,
    pub(crate) origin_sha256: String,
    pub(crate) injected_sha256: String,
    pub(crate) csp_nonce_applied: bool,
    /// Per-delivery handle written into the loader tag. Its UUID doubles as
    /// the page evidence ID, so the bootstrap can name exactly this instance.
    pub(crate) page_handle: String,
}

enum BufferedResponseKind {
    Json,
    SensorHtml {
        rule: SensorHtmlRule,
        nonce: Option<String>,
        page_handle: String,
    },
}

impl BufferedResponse {
    pub(crate) fn begin(
        response: &mut ResponseHeader,
        policy: BufferedResponsePolicy<'_>,
        reservation_bytes: usize,
        budget: &Arc<Semaphore>,
    ) -> Result<Self, ReasonCode> {
        let validation_reason = match policy {
            BufferedResponsePolicy::Json { .. } => ReasonCode::ResponseValidationFailed,
            BufferedResponsePolicy::SensorHtml(_) => ReasonCode::SensorHtmlValidationFailed,
        };
        let (limit, kind) = match policy {
            BufferedResponsePolicy::Json { max_bytes } if single_json_content_type(response) => {
                (max_bytes, BufferedResponseKind::Json)
            }
            BufferedResponsePolicy::SensorHtml(rule) if valid_html_response(response) => {
                let nonce = prepare_csp_nonce(response)?;
                (
                    rule.max_bytes(),
                    BufferedResponseKind::SensorHtml {
                        rule: rule.clone(),
                        nonce,
                        page_handle: format!("pgh_{}", uuid::Uuid::now_v7()),
                    },
                )
            }
            _ => return Err(validation_reason),
        };
        if matches!(response.status.as_u16(), 101 | 204 | 304)
            || !identity_encoding(response)
            || response.headers.contains_key("trailer")
        {
            return Err(validation_reason);
        }
        if let Some(length) = content_length(response)?
            && length > limit
        {
            return Err(ReasonCode::ResponseBodyTooLarge);
        }
        let minimum_reservation = limit
            .checked_mul(2)
            .ok_or(ReasonCode::ResponseBufferCapacityExhausted)?;
        let reservation_bytes = reservation_bytes.max(minimum_reservation);
        let permits = u32::try_from(reservation_bytes)
            .map_err(|_| ReasonCode::ResponseBufferCapacityExhausted)?;
        let permit = Arc::clone(budget)
            .try_acquire_many_owned(permits)
            .map_err(|_| ReasonCode::ResponseBufferCapacityExhausted)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| ReasonCode::ResponseBufferCapacityExhausted)?;
        Ok(Self {
            bytes,
            limit,
            kind,
            _permit: permit,
        })
    }

    pub(crate) fn filter(
        &mut self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<Option<BufferedEntity>, ReasonCode> {
        if let Some(chunk) = body.take() {
            let length = self
                .bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(ReasonCode::ResponseBodyTooLarge)?;
            if length > self.limit {
                return Err(ReasonCode::ResponseBodyTooLarge);
            }
            self.bytes.extend_from_slice(&chunk);
        }
        if !end_of_stream {
            return Ok(None);
        }
        match &self.kind {
            BufferedResponseKind::Json => {
                validate_strict_json(&self.bytes).map_err(ResponseGrantError::reason_code)?;
                Ok(Some(BufferedEntity {
                    body: Bytes::from(std::mem::take(&mut self.bytes)),
                    sensor_html: None,
                }))
            }
            BufferedResponseKind::SensorHtml {
                rule,
                nonce,
                page_handle,
            } => {
                let injected = rule
                    .inject(&self.bytes, nonce.as_deref(), page_handle)
                    .map_err(|_| ReasonCode::SensorHtmlValidationFailed)?;
                let transformation = SensorHtmlTransformation {
                    adapter_revision: injected.adapter_revision().to_owned(),
                    origin_sha256: injected.origin_sha256().to_owned(),
                    injected_sha256: injected.injected_sha256().to_owned(),
                    csp_nonce_applied: nonce.is_some(),
                    page_handle: page_handle.clone(),
                };
                Ok(Some(BufferedEntity {
                    body: Bytes::from(injected.into_body()),
                    sensor_html: Some(transformation),
                }))
            }
        }
    }
}

fn valid_html_response(response: &ResponseHeader) -> bool {
    if response.status.as_u16() != 200
        || response
            .headers
            .contains_key("content-security-policy-report-only")
        || response.headers.contains_key("content-disposition")
    {
        return false;
    }
    let mut values = response.headers.get_all("content-type").iter();
    let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    values.next().is_none()
        && value.split_once(';').is_some_and(|(media_type, charset)| {
            media_type.trim().eq_ignore_ascii_case("text/html")
                && charset.split_once('=').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("charset")
                        && value.trim().eq_ignore_ascii_case("utf-8")
                })
        })
}

fn prepare_csp_nonce(response: &mut ResponseHeader) -> Result<Option<String>, ReasonCode> {
    let policies = response
        .headers
        .get_all("content-security-policy")
        .iter()
        .map(|value| value.to_str().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ReasonCode::SensorHtmlValidationFailed)?;
    if policies.is_empty() {
        return Ok(None);
    }
    if policies.len() > 4 || policies.iter().any(|policy| policy.len() > 4096) {
        return Err(ReasonCode::SensorHtmlValidationFailed);
    }
    let mut random = [0_u8; 16];
    rand_bytes(&mut random).map_err(|_| ReasonCode::SensorHtmlValidationFailed)?;
    let nonce = hex(&random);
    let rewritten = policies
        .iter()
        .map(|policy| rewrite_csp_policy(policy, &nonce))
        .collect::<Result<Vec<_>, _>>()?;
    response.remove_header("content-security-policy");
    for policy in rewritten {
        response
            .append_header("Content-Security-Policy", policy)
            .map_err(|_| ReasonCode::SensorHtmlValidationFailed)?;
    }
    Ok(Some(nonce))
}

fn rewrite_csp_policy(policy: &str, nonce: &str) -> Result<String, ReasonCode> {
    if policy.is_empty() || policy.contains(',') {
        return Err(ReasonCode::SensorHtmlValidationFailed);
    }
    let directives = policy
        .split(';')
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .map(|directive| directive.split_ascii_whitespace().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut names = BTreeSet::new();
    for directive in &directives {
        let Some(name) = directive.first() else {
            return Err(ReasonCode::SensorHtmlValidationFailed);
        };
        let sandbox_blocks_scripts = name.eq_ignore_ascii_case("sandbox")
            && !directive
                .iter()
                .skip(1)
                .any(|value| value.eq_ignore_ascii_case("allow-scripts"));
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !names.insert(name.to_ascii_lowercase())
            || sandbox_blocks_scripts
        {
            return Err(ReasonCode::SensorHtmlValidationFailed);
        }
    }
    let has_script_policy = directives.iter().any(|directive| {
        directive[0].eq_ignore_ascii_case("script-src-elem")
            || directive[0].eq_ignore_ascii_case("script-src")
    });
    if !has_script_policy {
        return Err(ReasonCode::SensorHtmlValidationFailed);
    }
    let nonce_source = format!("'nonce-{nonce}'");
    Ok(directives
        .iter()
        .map(|directive| {
            let mut rendered = directive.join(" ");
            if directive[0].eq_ignore_ascii_case("script-src-elem")
                || directive[0].eq_ignore_ascii_case("script-src")
            {
                rendered.push(' ');
                rendered.push_str(&nonce_source);
            }
            rendered
        })
        .collect::<Vec<_>>()
        .join("; "))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn single_json_content_type(response: &ResponseHeader) -> bool {
    let mut values = response.headers.get_all("content-type").iter();
    let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    match parts.next() {
        None => true,
        Some(parameter) => {
            parts.next().is_none()
                && parameter.split_once('=').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("charset")
                        && value.trim().eq_ignore_ascii_case("utf-8")
                })
        }
    }
}

fn identity_encoding(response: &ResponseHeader) -> bool {
    let mut values = response.headers.get_all("content-encoding").iter();
    match values.next() {
        None => true,
        Some(value) => {
            values.next().is_none()
                && value
                    .to_str()
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity"))
        }
    }
}

fn content_length(response: &ResponseHeader) -> Result<Option<usize>, ReasonCode> {
    let mut values = response.headers.get_all("content-length").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ReasonCode::ResponseValidationFailed);
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse().ok())
        .map(Some)
        .ok_or(ReasonCode::ResponseValidationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xshield_gateway::{GatewayConfig, SENSOR_LOADER_PATH};

    const HTML: &[u8] = b"<!doctype html><html><head></head><body>ok</body></html>";

    fn response(content_type: &str, length: Option<usize>) -> ResponseHeader {
        let mut response = ResponseHeader::build(200, Some(2)).unwrap();
        response
            .insert_header("Content-Type", content_type)
            .unwrap();
        if let Some(length) = length {
            response
                .insert_header("Content-Length", length.to_string())
                .unwrap();
        }
        response
    }

    fn budget() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(1024))
    }

    #[test]
    fn withholds_chunks_until_one_valid_complete_json_body() {
        let mut buffer = BufferedResponse::begin(
            &mut response("application/json; charset=utf-8", Some(11)),
            BufferedResponsePolicy::Json { max_bytes: 64 },
            128,
            &budget(),
        )
        .unwrap();
        let mut first = Some(Bytes::from_static(br#"{"ok":"#));
        assert!(buffer.filter(&mut first, false).unwrap().is_none());
        assert!(first.is_none());

        let mut last = Some(Bytes::from_static(br"true}"));
        assert_eq!(
            buffer.filter(&mut last, true).unwrap().unwrap().body,
            Bytes::from_static(br#"{"ok":true}"#)
        );
        assert!(last.is_none());
    }

    #[test]
    fn rejects_oversize_encoded_or_invalid_json_without_releasing_a_chunk() {
        assert_eq!(
            BufferedResponse::begin(
                &mut response("application/json", Some(65)),
                BufferedResponsePolicy::Json { max_bytes: 64 },
                128,
                &budget(),
            )
            .err(),
            Some(ReasonCode::ResponseBodyTooLarge)
        );
        let mut encoded = response("application/json", None);
        encoded.insert_header("Content-Encoding", "gzip").unwrap();
        assert_eq!(
            BufferedResponse::begin(
                &mut encoded,
                BufferedResponsePolicy::Json { max_bytes: 64 },
                128,
                &budget(),
            )
            .err(),
            Some(ReasonCode::ResponseValidationFailed)
        );
        let mut trailer = response("application/json", None);
        trailer.insert_header("Trailer", "Digest").unwrap();
        assert_eq!(
            BufferedResponse::begin(
                &mut trailer,
                BufferedResponsePolicy::Json { max_bytes: 64 },
                128,
                &budget(),
            )
            .err(),
            Some(ReasonCode::ResponseValidationFailed)
        );

        let mut buffer = BufferedResponse::begin(
            &mut response("application/json", None),
            BufferedResponsePolicy::Json { max_bytes: 64 },
            128,
            &budget(),
        )
        .unwrap();
        let mut body = Some(Bytes::from_static(b"not-json"));
        assert!(matches!(
            buffer.filter(&mut body, true),
            Err(ReasonCode::ResponseValidationFailed)
        ));
        assert!(body.is_none());

        let mut ambiguous = BufferedResponse::begin(
            &mut response("application/json", None),
            BufferedResponsePolicy::Json { max_bytes: 64 },
            128,
            &budget(),
        )
        .unwrap();
        let mut body = Some(Bytes::from_static(br#"{"id":"a","id":"b"}"#));
        assert!(matches!(
            ambiguous.filter(&mut body, true),
            Err(ReasonCode::ResponseValidationFailed)
        ));
    }

    #[test]
    fn rejects_ambiguous_content_type_parameters() {
        assert!(
            BufferedResponse::begin(
                &mut response("application/json; charset=utf-8; charset=utf-8", None),
                BufferedResponsePolicy::Json { max_bytes: 64 },
                128,
                &budget()
            )
            .is_err()
        );
    }

    #[test]
    fn holds_and_releases_aggregate_buffer_capacity() {
        let budget = Arc::new(Semaphore::new(192));
        let mut first = BufferedResponse::begin(
            &mut response("application/json", None),
            BufferedResponsePolicy::Json { max_bytes: 64 },
            192,
            &budget,
        )
        .unwrap();
        let mut body = Some(Bytes::from_static(br#"{"ok":true}"#));
        first.filter(&mut body, true).unwrap();
        assert_eq!(
            BufferedResponse::begin(
                &mut response("application/json", None),
                BufferedResponsePolicy::Json { max_bytes: 1 },
                2,
                &budget,
            )
            .err(),
            Some(ReasonCode::ResponseBufferCapacityExhausted)
        );
        drop(first);
        BufferedResponse::begin(
            &mut response("application/json", None),
            BufferedResponsePolicy::Json { max_bytes: 64 },
            192,
            &budget,
        )
        .unwrap();
        let undersized_budget = Arc::new(Semaphore::new(127));
        assert_eq!(
            BufferedResponse::begin(
                &mut response("application/json", None),
                BufferedResponsePolicy::Json { max_bytes: 64 },
                64,
                &undersized_budget,
            )
            .err(),
            Some(ReasonCode::ResponseBufferCapacityExhausted)
        );
    }

    #[test]
    fn injects_only_approved_utf8_html_without_csp() {
        let config = GatewayConfig::from_json(
            br#"{
              "listen":"127.0.0.1:6188",
              "origin":{"address":"127.0.0.1:8080","server_name":"origin.example","tls":false},
              "tenant_id":"tenant_demo","site_id":"site_demo","policy_revision":"policy-r1",
              "audit":{"directory":"target/audit","key_id":"journal-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
              "identity_store":{"max_connections":1,"acquire_timeout_ms":1000},
              "sensor":{"origin":"https://app.example","build_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","heartbeat_seconds":15},
              "operations":[{"operation_id":"home.read","method":"GET","path":"/","admission":"PUBLIC","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"SENSOR_HTML","max_bytes":128,"adapter_revision":"home-r1","origin_sha256":"8afe2e0204ebb1d838fdd6ce33cfb526ad18ca0d3877cc1a3768a778332c054a","injection_offset":27}}]
            }"#,
        )
        .unwrap();
        let policy = config.buffered_response_policy("GET", "/").unwrap();
        let mut html_response = response("text/html; charset=utf-8", Some(HTML.len()));
        let mut buffer =
            BufferedResponse::begin(&mut html_response, policy, 512, &budget()).unwrap();
        let mut body = Some(Bytes::from_static(HTML));
        let complete = buffer.filter(&mut body, true).unwrap().unwrap();
        assert!(complete.sensor_html.is_some());
        assert!(
            std::str::from_utf8(&complete.body)
                .unwrap()
                .contains(SENSOR_LOADER_PATH)
        );

        let mut csp_response = response("text/html; charset=utf-8", Some(HTML.len()));
        csp_response
            .insert_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; require-sri-for script; object-src 'none'",
            )
            .unwrap();
        csp_response
            .append_header("Content-Security-Policy", "script-src-elem 'none'")
            .unwrap();
        let mut buffer =
            BufferedResponse::begin(&mut csp_response, policy, 512, &budget()).unwrap();
        let policies = csp_response
            .headers
            .get_all("content-security-policy")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(policies.len(), 2);
        let nonce = policies[0]
            .split_ascii_whitespace()
            .find_map(|value| {
                value
                    .trim_end_matches(';')
                    .strip_prefix("'nonce-")?
                    .strip_suffix('\'')
            })
            .unwrap();
        assert!(policies.iter().all(|policy| policy.contains(nonce)));
        let mut body = Some(Bytes::from_static(HTML));
        let complete = buffer.filter(&mut body, true).unwrap().unwrap();
        assert!(complete.sensor_html.unwrap().csp_nonce_applied);
        assert!(
            std::str::from_utf8(&complete.body)
                .unwrap()
                .contains(&format!("nonce=\"{nonce}\""))
        );

        html_response
            .insert_header("Content-Security-Policy", "default-src 'self'")
            .unwrap();
        assert!(matches!(
            BufferedResponse::begin(&mut html_response, policy, 512, &budget()),
            Err(ReasonCode::SensorHtmlValidationFailed)
        ));
    }
}
