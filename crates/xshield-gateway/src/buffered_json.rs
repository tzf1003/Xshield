use bytes::Bytes;
use pingora::http::ResponseHeader;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use xshield_core::audit::ReasonCode;
use xshield_gateway::response_grant::{ResponseGrantError, validate_strict_json};

pub(crate) struct BufferedJsonResponse {
    bytes: Vec<u8>,
    limit: usize,
    _permit: OwnedSemaphorePermit,
}

impl BufferedJsonResponse {
    pub(crate) fn begin(
        response: &ResponseHeader,
        limit: usize,
        budget: &Arc<Semaphore>,
    ) -> Result<Self, ReasonCode> {
        if matches!(response.status.as_u16(), 101 | 204 | 304)
            || !single_json_content_type(response)
            || !identity_encoding(response)
        {
            return Err(ReasonCode::ResponseValidationFailed);
        }
        if let Some(length) = content_length(response)?
            && length > limit
        {
            return Err(ReasonCode::ResponseBodyTooLarge);
        }
        let permits = u32::try_from(limit).map_err(|_| ReasonCode::ResponseBodyTooLarge)?;
        let permit = Arc::clone(budget)
            .try_acquire_many_owned(permits)
            .map_err(|_| ReasonCode::ResponseBufferCapacityExhausted)?;
        Ok(Self {
            bytes: Vec::new(),
            limit,
            _permit: permit,
        })
    }

    pub(crate) fn filter(
        &mut self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<(), ReasonCode> {
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
            return Ok(());
        }
        validate_strict_json(&self.bytes).map_err(ResponseGrantError::reason_code)?;
        *body = Some(Bytes::from(std::mem::take(&mut self.bytes)));
        Ok(())
    }
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
        let mut buffer = BufferedJsonResponse::begin(
            &response("application/json; charset=utf-8", Some(11)),
            64,
            &budget(),
        )
        .unwrap();
        let mut first = Some(Bytes::from_static(br#"{"ok":"#));
        buffer.filter(&mut first, false).unwrap();
        assert!(first.is_none());

        let mut last = Some(Bytes::from_static(br"true}"));
        buffer.filter(&mut last, true).unwrap();
        assert_eq!(last.unwrap(), Bytes::from_static(br#"{"ok":true}"#));
    }

    #[test]
    fn rejects_oversize_encoded_or_invalid_json_without_releasing_a_chunk() {
        assert_eq!(
            BufferedJsonResponse::begin(&response("application/json", Some(65)), 64, &budget())
                .err(),
            Some(ReasonCode::ResponseBodyTooLarge)
        );
        let mut encoded = response("application/json", None);
        encoded.insert_header("Content-Encoding", "gzip").unwrap();
        assert_eq!(
            BufferedJsonResponse::begin(&encoded, 64, &budget()).err(),
            Some(ReasonCode::ResponseValidationFailed)
        );

        let mut buffer =
            BufferedJsonResponse::begin(&response("application/json", None), 64, &budget())
                .unwrap();
        let mut body = Some(Bytes::from_static(b"not-json"));
        assert_eq!(
            buffer.filter(&mut body, true),
            Err(ReasonCode::ResponseValidationFailed)
        );
        assert!(body.is_none());

        let mut ambiguous =
            BufferedJsonResponse::begin(&response("application/json", None), 64, &budget())
                .unwrap();
        let mut body = Some(Bytes::from_static(br#"{"id":"a","id":"b"}"#));
        assert_eq!(
            ambiguous.filter(&mut body, true),
            Err(ReasonCode::ResponseValidationFailed)
        );
    }

    #[test]
    fn rejects_ambiguous_content_type_parameters() {
        assert!(
            BufferedJsonResponse::begin(
                &response("application/json; charset=utf-8; charset=utf-8", None),
                64,
                &budget()
            )
            .is_err()
        );
    }

    #[test]
    fn holds_and_releases_aggregate_buffer_capacity() {
        let budget = Arc::new(Semaphore::new(64));
        let mut first =
            BufferedJsonResponse::begin(&response("application/json", None), 64, &budget).unwrap();
        let mut body = Some(Bytes::from_static(br#"{"ok":true}"#));
        first.filter(&mut body, true).unwrap();
        assert_eq!(
            BufferedJsonResponse::begin(&response("application/json", None), 1, &budget).err(),
            Some(ReasonCode::ResponseBufferCapacityExhausted)
        );
        drop(first);
        BufferedJsonResponse::begin(&response("application/json", None), 64, &budget).unwrap();
    }
}
