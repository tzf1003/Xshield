//! Minimal blocking S3 REST client: the handful of object and bucket calls the
//! evidence vault needs, signed with `SigV4` and bounded in size and time.
//!
//! Errors never carry response bodies or credentials. Transport failures and
//! unexpected statuses become [`EvidenceError::Io`], which retention treats as
//! retryable; a missing object is reported as `None` so each caller decides
//! between "unavailable" and "already absent".

use super::sigv4::{self, CanonicalRequest, EMPTY_PAYLOAD_SHA256};
use super::{S3Addressing, S3EvidenceStoreConfig, S3ObjectLockMode};
use crate::EvidenceError;
use chrono::{DateTime, SecondsFormat, Utc};
use openssl::{base64, sha::sha256};
use std::io;
use ureq::{Agent, http::Response};

/// Largest XML document accepted from a bucket or list call.
const XML_BYTES_MAX: u64 = 1024 * 1024;
/// Keys requested per `ListObjectsV2` page.
const LIST_PAGE_KEYS: u16 = 1000;
/// Bodies at or under this size use one conditional `PUT`; larger ones use
/// multipart upload, split into parts of this same size (the last part may
/// be smaller). Above the service minimum of 5 MiB for a non-final part, so
/// every part but the last qualifies.
pub(super) const MULTIPART_THRESHOLD_BYTES: usize = 8 * 1024 * 1024;
/// S3 allows at most 10,000 parts per upload; this body size and part size
/// stay far under that, so this is only a defensive sanity bound.
const MULTIPART_PARTS_MAX: usize = 10_000;

pub(super) struct S3Client {
    agent: Agent,
    config: S3EvidenceStoreConfig,
}

/// A fetched object with the version that holds exactly these bytes.
pub(super) struct FetchedObject {
    pub bytes: Vec<u8>,
    pub version_id: Option<String>,
}

/// Object metadata from `HEAD`.
pub(super) struct ObjectHead {
    pub bytes: u64,
    pub version_id: Option<String>,
    pub last_modified: DateTime<Utc>,
    pub retain_until: Option<DateTime<Utc>>,
    /// The bucket's own server-side encryption, such as `"aws:kms"`; `None`
    /// when the bucket applied none. Independent of this crate's envelope.
    /// Observed only by tests, which confirm the header this crate asks for
    /// was actually honored; no caller needs it at run time.
    #[cfg(test)]
    pub server_side_encryption: Option<String>,
}

/// One key from `ListObjectsV2`.
pub(super) struct ListedObject {
    pub key: String,
    pub bytes: u64,
    pub last_modified: DateTime<Utc>,
}

pub(super) struct ListPage {
    pub objects: Vec<ListedObject>,
    pub truncated: bool,
}

impl S3Client {
    pub(super) fn new(config: S3EvidenceStoreConfig) -> Self {
        let agent = Agent::config_builder()
            .http_status_as_error(false)
            // Credentials and evidence go to the configured endpoint only:
            // no environment proxy and no redirects.
            .proxy(None)
            .max_redirects(0)
            .https_only(!config.allow_plain_http)
            .timeout_global(Some(config.request_timeout))
            .build()
            .new_agent();
        Self { agent, config }
    }

    pub(super) const fn config(&self) -> &S3EvidenceStoreConfig {
        &self.config
    }

    /// Stores `body` under `key` only if no current object has that key.
    ///
    /// With object lock configured, the object is locked until `retain_until`.
    /// A `body` above [`MULTIPART_THRESHOLD_BYTES`] goes through a multipart
    /// upload instead of one request; completion is still conditional, so
    /// the create-only guarantee is the same either way.
    pub(super) fn put_new(
        &self,
        key: &str,
        body: &[u8],
        retain_until: DateTime<Utc>,
    ) -> Result<(), EvidenceError> {
        if body.len() > MULTIPART_THRESHOLD_BYTES {
            self.put_new_multipart(key, body, retain_until)
        } else {
            self.put_new_single(key, body, retain_until)
        }
    }

    fn put_new_single(
        &self,
        key: &str,
        body: &[u8],
        retain_until: DateTime<Utc>,
    ) -> Result<(), EvidenceError> {
        let payload_sha256 = sha256(body);
        let mut headers = vec![
            (
                "content-type".to_owned(),
                "application/octet-stream".to_owned(),
            ),
            ("if-none-match".to_owned(), "*".to_owned()),
            (
                "x-amz-checksum-sha256".to_owned(),
                base64::encode_block(&payload_sha256),
            ),
        ];
        headers.extend(self.object_lock_headers(retain_until));
        headers.extend(self.sse_headers());
        let response = self.send(
            "PUT",
            Some(key),
            "",
            headers,
            Some((body, &sigv4::lower_hex(&payload_sha256))),
        )?;
        match response.status().as_u16() {
            200 => Ok(()),
            412 => Err(EvidenceError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "evidence object already exists",
            ))),
            status => Err(status_error(status)),
        }
    }

    /// Uploads `body` as a multipart upload, completing only if no current
    /// object has `key`. A failure aborts the upload so it does not linger
    /// as an invisible, billable partial object.
    fn put_new_multipart(
        &self,
        key: &str,
        body: &[u8],
        retain_until: DateTime<Utc>,
    ) -> Result<(), EvidenceError> {
        let upload_id = self.create_multipart_upload(key, retain_until)?;
        match self.upload_parts_and_complete(key, &upload_id, body) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.abort_multipart_upload(key, &upload_id);
                Err(error)
            }
        }
    }

    fn create_multipart_upload(
        &self,
        key: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<String, EvidenceError> {
        // No `x-amz-checksum-algorithm` here: declaring one would require
        // echoing every part's checksum back in the completion XML below,
        // and signing already covers transport integrity per request; the
        // manifest's own digest covers the reassembled object.
        let mut headers = vec![(
            "content-type".to_owned(),
            "application/octet-stream".to_owned(),
        )];
        headers.extend(self.object_lock_headers(retain_until));
        headers.extend(self.sse_headers());
        let mut response = self.send(
            "POST",
            Some(key),
            "uploads=",
            headers,
            Some((&[], EMPTY_PAYLOAD_SHA256)),
        )?;
        match response.status().as_u16() {
            200 => {}
            status => return Err(status_error(status)),
        }
        let body = read_bounded(&mut response, XML_BYTES_MAX)
            .map_err(|()| protocol_error("oversized multipart-create response"))?;
        let body = std::str::from_utf8(&body)
            .map_err(|_| protocol_error("non-UTF-8 multipart-create response"))?;
        xml_elements(body, "UploadId")
            .next()
            .map(str::to_owned)
            .ok_or_else(|| protocol_error("multipart create without upload id"))
    }

    /// Uploads every part of `body`, then completes the upload create-only.
    fn upload_parts_and_complete(
        &self,
        key: &str,
        upload_id: &str,
        body: &[u8],
    ) -> Result<(), EvidenceError> {
        let chunks = body.chunks(MULTIPART_THRESHOLD_BYTES);
        if chunks.len() > MULTIPART_PARTS_MAX {
            return Err(EvidenceError::UnsafePath);
        }
        let mut parts = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.enumerate() {
            let part_number = u16::try_from(index + 1).map_err(|_| EvidenceError::UnsafePath)?;
            let etag = self.upload_part(key, upload_id, part_number, chunk)?;
            parts.push((part_number, etag));
        }
        self.complete_multipart_upload(key, upload_id, &parts)
    }

    fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u16,
        body: &[u8],
    ) -> Result<String, EvidenceError> {
        let payload_sha256 = sha256(body);
        let query = format!(
            "partNumber={part_number}&uploadId={}",
            sigv4::uri_encode(upload_id, false)
        );
        let response = self.send(
            "PUT",
            Some(key),
            &query,
            Vec::new(),
            Some((body, &sigv4::lower_hex(&payload_sha256))),
        )?;
        match response.status().as_u16() {
            200 => {}
            status => return Err(status_error(status)),
        }
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| protocol_error("upload part without etag"))?;
        // Carried verbatim into the completion XML below as element text; it
        // never needs `<` or `&`, so reject rather than escape it.
        if etag.bytes().any(|byte| byte == b'<' || byte == b'&') {
            return Err(protocol_error("unsafe etag"));
        }
        Ok(etag.to_owned())
    }

    fn complete_multipart_upload(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[(u16, String)],
    ) -> Result<(), EvidenceError> {
        use std::fmt::Write as _;
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (number, etag) in parts {
            let _ = write!(
                xml,
                "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
            );
        }
        xml.push_str("</CompleteMultipartUpload>");
        let payload_sha256 = sha256(xml.as_bytes());
        let headers = vec![
            ("content-type".to_owned(), "application/xml".to_owned()),
            ("if-none-match".to_owned(), "*".to_owned()),
        ];
        let query = format!("uploadId={}", sigv4::uri_encode(upload_id, false));
        let response = self.send(
            "POST",
            Some(key),
            &query,
            headers,
            Some((xml.as_bytes(), &sigv4::lower_hex(&payload_sha256))),
        )?;
        match response.status().as_u16() {
            200 => Ok(()),
            412 => Err(EvidenceError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "evidence object already exists",
            ))),
            status => Err(status_error(status)),
        }
    }

    /// Best-effort cleanup of an upload that will never complete; the bucket
    /// also expires abandoned multipart uploads on its own lifecycle rules.
    fn abort_multipart_upload(&self, key: &str, upload_id: &str) -> Result<(), EvidenceError> {
        let query = format!("uploadId={}", sigv4::uri_encode(upload_id, false));
        let response = self.send("DELETE", Some(key), &query, Vec::new(), None)?;
        match response.status().as_u16() {
            200 | 204 | 404 => Ok(()),
            status => Err(status_error(status)),
        }
    }

    /// Headers requesting the configured object lock; empty when unset.
    fn object_lock_headers(&self, retain_until: DateTime<Utc>) -> Vec<(String, String)> {
        let Some(mode) = self.config.object_lock else {
            return Vec::new();
        };
        vec![
            (
                "x-amz-object-lock-mode".to_owned(),
                match mode {
                    S3ObjectLockMode::Governance => "GOVERNANCE",
                    S3ObjectLockMode::Compliance => "COMPLIANCE",
                }
                .to_owned(),
            ),
            (
                "x-amz-object-lock-retain-until-date".to_owned(),
                retain_until.to_rfc3339_opts(SecondsFormat::Millis, true),
            ),
        ]
    }

    /// Headers requesting the configured bucket-side SSE-KMS; empty when
    /// unset, in which case only this crate's own envelope encrypts the
    /// object.
    fn sse_headers(&self) -> Vec<(String, String)> {
        let Some(sse) = &self.config.sse_kms else {
            return Vec::new();
        };
        let mut headers = vec![(
            "x-amz-server-side-encryption".to_owned(),
            "aws:kms".to_owned(),
        )];
        if let Some(key_id) = &sse.key_id {
            headers.push((
                "x-amz-server-side-encryption-aws-kms-key-id".to_owned(),
                key_id.clone(),
            ));
        }
        headers
    }

    /// Fetches at most `max_bytes`, or `None` when the key has no current object.
    pub(super) fn get_bounded(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> Result<Option<FetchedObject>, EvidenceError> {
        let mut response = self.send("GET", Some(key), "", Vec::new(), None)?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            status => return Err(status_error(status)),
        }
        if response
            .body()
            .content_length()
            .is_some_and(|length| length > max_bytes)
        {
            return Err(EvidenceError::UnsafePath);
        }
        let version_id = version_id(&response);
        let bytes =
            read_bounded(&mut response, max_bytes).map_err(|()| EvidenceError::UnsafePath)?;
        Ok(Some(FetchedObject { bytes, version_id }))
    }

    /// Reads object metadata, or `None` when the key has no current object.
    pub(super) fn head(&self, key: &str) -> Result<Option<ObjectHead>, EvidenceError> {
        let response = self.send("HEAD", Some(key), "", Vec::new(), None)?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            status => return Err(status_error(status)),
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
        };
        let bytes = header("content-length")
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| protocol_error("HEAD without content length"))?;
        let last_modified = header("last-modified")
            .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
            .ok_or_else(|| protocol_error("HEAD without last modified"))?
            .with_timezone(&Utc);
        let retain_until = match header("x-amz-object-lock-retain-until-date") {
            Some(value) => Some(
                DateTime::parse_from_rfc3339(value)
                    .map_err(|_| protocol_error("malformed retention date"))?
                    .with_timezone(&Utc),
            ),
            None => None,
        };
        Ok(Some(ObjectHead {
            bytes,
            version_id: version_id(&response),
            last_modified,
            retain_until,
            #[cfg(test)]
            server_side_encryption: header("x-amz-server-side-encryption").map(str::to_owned),
        }))
    }

    /// Permanently deletes one version, or the unversioned object.
    ///
    /// Deleting the current key of a versioned bucket would only add a delete
    /// marker and keep the ciphertext, so callers pass the version they read.
    pub(super) fn delete(&self, key: &str, version_id: Option<&str>) -> Result<(), EvidenceError> {
        let query = version_id
            .map(|version| format!("versionId={}", sigv4::uri_encode(version, false)))
            .unwrap_or_default();
        let response = self.send("DELETE", Some(key), &query, Vec::new(), None)?;
        match response.status().as_u16() {
            200 | 204 | 404 => Ok(()),
            status => Err(status_error(status)),
        }
    }

    /// Lists keys under `prefix` that sort after `start_after`.
    pub(super) fn list(&self, prefix: &str, start_after: &str) -> Result<ListPage, EvidenceError> {
        let mut query = vec![
            ("list-type", "2".to_owned()),
            ("max-keys", LIST_PAGE_KEYS.to_string()),
            ("prefix", prefix.to_owned()),
        ];
        if !start_after.is_empty() {
            query.push(("start-after", start_after.to_owned()));
        }
        query.sort_by(|left, right| left.0.cmp(right.0));
        let query = query
            .iter()
            .map(|(name, value)| format!("{name}={}", sigv4::uri_encode(value, false)))
            .collect::<Vec<_>>()
            .join("&");
        let body = self
            .bucket_document(&query)?
            .ok_or_else(|| protocol_error("bucket missing"))?;
        let body = std::str::from_utf8(&body).map_err(|_| protocol_error("non-UTF-8 listing"))?;
        let mut objects = Vec::new();
        for entry in xml_elements(body, "Contents") {
            let key = xml_elements(entry, "Key")
                .next()
                .map(xml_unescape)
                .ok_or_else(|| protocol_error("listing entry without key"))?;
            let bytes = xml_elements(entry, "Size")
                .next()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| protocol_error("listing entry without size"))?;
            let last_modified = xml_elements(entry, "LastModified")
                .next()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .ok_or_else(|| protocol_error("listing entry without time"))?
                .with_timezone(&Utc);
            objects.push(ListedObject {
                key,
                bytes,
                last_modified,
            });
        }
        let truncated = xml_elements(body, "IsTruncated").next() == Some("true");
        Ok(ListPage { objects, truncated })
    }

    /// Returns whether bucket versioning is enabled.
    pub(super) fn versioning_enabled(&self) -> Result<bool, EvidenceError> {
        let body = self
            .bucket_document("versioning=")?
            .ok_or_else(|| protocol_error("bucket missing"))?;
        let body = String::from_utf8_lossy(&body);
        Ok(xml_elements(&body, "Status").next() == Some("Enabled"))
    }

    /// Returns whether the bucket was created with object lock enabled.
    pub(super) fn object_lock_enabled(&self) -> Result<bool, EvidenceError> {
        let Some(body) = self.bucket_document("object-lock=")? else {
            return Ok(false);
        };
        let body = String::from_utf8_lossy(&body);
        Ok(xml_elements(&body, "ObjectLockEnabled").next() == Some("Enabled"))
    }

    /// GETs a bucket subresource; `None` for 404 (no bucket or no configuration).
    fn bucket_document(&self, query: &str) -> Result<Option<Vec<u8>>, EvidenceError> {
        let mut response = self.send("GET", None, query, Vec::new(), None)?;
        match response.status().as_u16() {
            200 => {}
            404 => return Ok(None),
            status => return Err(status_error(status)),
        }
        read_bounded(&mut response, XML_BYTES_MAX)
            .map(Some)
            .map_err(|()| protocol_error("oversized bucket document"))
    }

    /// Creates the bucket, optionally with object lock (tests and setup only).
    #[cfg(test)]
    pub(super) fn create_bucket(&self, object_lock: bool) -> Result<(), EvidenceError> {
        let mut headers = Vec::new();
        if object_lock {
            headers.push((
                "x-amz-bucket-object-lock-enabled".to_owned(),
                "true".to_owned(),
            ));
        }
        // An explicit empty body: without Content-Length the request is
        // chunked and the service expects a bucket configuration document.
        let response = self.send("PUT", None, "", headers, Some((&[], EMPTY_PAYLOAD_SHA256)))?;
        match response.status().as_u16() {
            200 => Ok(()),
            status => Err(status_error(status)),
        }
    }

    /// Returns whether one specific version of `key` still exists.
    #[cfg(test)]
    pub(super) fn version_exists(
        &self,
        key: &str,
        version_id: &str,
    ) -> Result<bool, EvidenceError> {
        let query = format!("versionId={}", sigv4::uri_encode(version_id, false));
        let response = self.send("HEAD", Some(key), &query, Vec::new(), None)?;
        match response.status().as_u16() {
            200 => Ok(true),
            // MinIO answers 400 for a version ID it no longer knows.
            400 | 404 => Ok(false),
            status => Err(status_error(status)),
        }
    }

    /// Writes raw bytes over an existing key, bypassing `If-None-Match`, so a
    /// test can stand in for tampering with the bucket.
    #[cfg(test)]
    pub(super) fn overwrite(&self, key: &str, body: &[u8]) -> Result<(), EvidenceError> {
        let payload_sha256 = sha256(body);
        let headers = vec![(
            "x-amz-checksum-sha256".to_owned(),
            base64::encode_block(&payload_sha256),
        )];
        let response = self.send(
            "PUT",
            Some(key),
            "",
            headers,
            Some((body, &sigv4::lower_hex(&payload_sha256))),
        )?;
        match response.status().as_u16() {
            200 => Ok(()),
            status => Err(status_error(status)),
        }
    }

    fn send(
        &self,
        method: &str,
        key: Option<&str>,
        query: &str,
        mut headers: Vec<(String, String)>,
        body: Option<(&[u8], &str)>,
    ) -> Result<Response<ureq::Body>, EvidenceError> {
        let config = &self.config;
        let (host, path) = match config.addressing {
            S3Addressing::Path => (
                config.authority.clone(),
                match key {
                    Some(key) => format!("/{}/{}", config.bucket, sigv4::uri_encode(key, true)),
                    None => format!("/{}", config.bucket),
                },
            ),
            S3Addressing::VirtualHosted => (
                format!("{}.{}", config.bucket, config.authority),
                match key {
                    Some(key) => format!("/{}", sigv4::uri_encode(key, true)),
                    None => "/".to_owned(),
                },
            ),
        };
        let now = Utc::now();
        let payload_sha256 = body.map_or(EMPTY_PAYLOAD_SHA256, |(_, digest)| digest);
        headers.push(("host".to_owned(), host.clone()));
        headers.push(("x-amz-date".to_owned(), sigv4::amz_date(now)));
        headers.push(("x-amz-content-sha256".to_owned(), payload_sha256.to_owned()));
        if let Some(token) = &config.credentials.session_token {
            headers.push(("x-amz-security-token".to_owned(), token.as_str().to_owned()));
        }
        let authorization = sigv4::authorization(
            &config.credentials.access_key_id,
            &config.credentials.secret_access_key,
            &config.region,
            &CanonicalRequest {
                method,
                path: &path,
                query,
                headers: &headers,
                payload_sha256,
            },
            now,
        )?;
        let mut url = format!("{}://{host}{path}", config.scheme);
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        let mut request = ureq::http::Request::builder().method(method).uri(url);
        for (name, value) in &headers {
            // ureq derives Host from the URI, which is the value signed above.
            if name != "host" {
                request = request.header(name, value);
            }
        }
        request = request.header("authorization", authorization);
        match body {
            Some((bytes, _)) => request
                .body(bytes)
                .map_err(|_| protocol_error("invalid request"))
                .and_then(|request| self.agent.run(request).map_err(transport_error)),
            None => request
                .body(())
                .map_err(|_| protocol_error("invalid request"))
                .and_then(|request| self.agent.run(request).map_err(transport_error)),
        }
    }
}

/// Reads the whole body if it is at most `max_bytes`. ureq's own limit fails
/// a body of exactly the limit, so it is given one byte of headroom.
fn read_bounded(response: &mut Response<ureq::Body>, max_bytes: u64) -> Result<Vec<u8>, ()> {
    let bytes = response
        .body_mut()
        .with_config()
        .limit(max_bytes.saturating_add(1))
        .read_to_vec()
        .map_err(|_| ())?;
    if bytes.len() as u64 > max_bytes {
        return Err(());
    }
    Ok(bytes)
}

fn version_id(response: &Response<ureq::Body>) -> Option<String> {
    response
        .headers()
        .get("x-amz-version-id")
        .and_then(|value| value.to_str().ok())
        // Unversioned buckets report the literal "null" version.
        .filter(|value| !value.is_empty() && *value != "null")
        .map(str::to_owned)
}

fn status_error(status: u16) -> EvidenceError {
    EvidenceError::Io(io::Error::other(format!(
        "evidence object store returned HTTP {status}"
    )))
}

fn protocol_error(message: &'static str) -> EvidenceError {
    EvidenceError::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[allow(clippy::needless_pass_by_value)]
fn transport_error(error: ureq::Error) -> EvidenceError {
    let kind = match error {
        ureq::Error::Timeout(_) => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    };
    EvidenceError::Io(io::Error::new(kind, "evidence object store unreachable"))
}

/// Yields the text inside each `<tag>…</tag>` of a flat S3 XML document.
/// S3 responses neither nest an element in one of the same name nor use
/// attributes on the elements read here.
fn xml_elements<'a>(document: &'a str, tag: &str) -> impl Iterator<Item = &'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = document;
    std::iter::from_fn(move || {
        let start = rest.find(&open)? + open.len();
        let end = rest[start..].find(&close)? + start;
        let element = &rest[start..end];
        rest = &rest[end + close.len()..];
        Some(element)
    })
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_flat_xml_elements() {
        let document = "<ListBucketResult><IsTruncated>false</IsTruncated>\
            <Contents><Key>a&amp;b.xev</Key><Size>7</Size></Contents>\
            <Contents><Key>c.xev</Key><Size>9</Size></Contents></ListBucketResult>";
        let keys = xml_elements(document, "Contents")
            .filter_map(|entry| xml_elements(entry, "Key").next().map(xml_unescape))
            .collect::<Vec<_>>();
        assert_eq!(keys, ["a&b.xev", "c.xev"]);
        assert_eq!(xml_elements(document, "IsTruncated").next(), Some("false"));
        assert_eq!(xml_elements(document, "Missing").next(), None);
        assert_eq!(xml_elements("<Key>unterminated", "Key").next(), None);
    }
}
