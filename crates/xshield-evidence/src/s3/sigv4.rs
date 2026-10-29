//! AWS Signature Version 4 for the S3 REST requests this adapter sends.
//!
//! Only header-based signing with a known payload hash is implemented: every
//! request body is a complete, already-encrypted object held in memory, so
//! chunked or unsigned payloads are never needed.

use crate::EvidenceError;
use chrono::{DateTime, Utc};
use openssl::{hash::MessageDigest, pkey::PKey, sha::sha256, sign::Signer};
use zeroize::Zeroizing;

/// SHA-256 of the empty payload, used by every bodiless request.
pub(super) const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// One request to sign. Header names must be lowercase and values trimmed;
/// `host`, `x-amz-date` and `x-amz-content-sha256` must be among them.
pub(super) struct CanonicalRequest<'a> {
    pub method: &'a str,
    /// Already URI-encoded absolute path.
    pub path: &'a str,
    /// Already encoded, sorted `name=value` pairs joined by `&`.
    pub query: &'a str,
    pub headers: &'a [(String, String)],
    pub payload_sha256: &'a str,
}

/// Returns the `Authorization` header value for `request` at `time`.
///
/// # Errors
/// Returns [`EvidenceError::Crypto`] when HMAC setup fails.
pub(super) fn authorization(
    access_key_id: &str,
    secret_access_key: &Zeroizing<String>,
    region: &str,
    request: &CanonicalRequest<'_>,
    time: DateTime<Utc>,
) -> Result<String, EvidenceError> {
    let mut headers = request.headers.iter().collect::<Vec<_>>();
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical = format!("{}\n{}\n{}\n", request.method, request.path, request.query);
    for (name, value) in &headers {
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(value);
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed_headers);
    canonical.push('\n');
    canonical.push_str(request.payload_sha256);
    let date = time.format("%Y%m%d").to_string();
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        amz_date(time),
        lower_hex(&sha256(canonical.as_bytes()))
    );
    let secret = Zeroizing::new(format!("AWS4{}", secret_access_key.as_str()));
    let date_key = hmac(secret.as_bytes(), date.as_bytes())?;
    let region_key = hmac(&date_key, region.as_bytes())?;
    let service_key = hmac(&region_key, b"s3")?;
    let signing_key = hmac(&service_key, b"aws4_request")?;
    let signature = hmac(&signing_key, string_to_sign.as_bytes())?;
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={}",
        lower_hex(&signature)
    ))
}

/// The `x-amz-date` form of `time`.
pub(super) fn amz_date(time: DateTime<Utc>) -> String {
    time.format("%Y%m%dT%H%M%SZ").to_string()
}

/// S3's URI encoding: every byte except unreserved characters, and `/` too
/// unless `keep_slash` (object key paths keep their separators).
pub(super) fn uri_encode(value: &str, keep_slash: bool) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && byte == b'/')
        {
            output.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

pub(super) fn lower_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hmac(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
    let key = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(data)?;
    Ok(Zeroizing::new(signer.sign_to_vec()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // Examples from the Amazon S3 API reference, "Signature Calculations for
    // the Authorization Header: Transferring Payload in a Single Chunk".
    const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn example_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).single().unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn signs_the_aws_get_object_example() {
        let headers = headers(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let value = authorization(
            ACCESS_KEY,
            &Zeroizing::new(SECRET_KEY.to_owned()),
            "us-east-1",
            &CanonicalRequest {
                method: "GET",
                path: "/test.txt",
                query: "",
                headers: &headers,
                payload_sha256: EMPTY_PAYLOAD_SHA256,
            },
            example_time(),
        )
        .unwrap();
        assert_eq!(
            value,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn signs_the_aws_put_object_example() {
        let payload = lower_hex(&sha256(b"Welcome to Amazon S3."));
        let headers = headers(&[
            ("date", "Fri, 24 May 2013 00:00:00 GMT"),
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", &payload),
            ("x-amz-date", "20130524T000000Z"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ]);
        let value = authorization(
            ACCESS_KEY,
            &Zeroizing::new(SECRET_KEY.to_owned()),
            "us-east-1",
            &CanonicalRequest {
                method: "PUT",
                path: &format!("/{}", uri_encode("test$file.text", true)),
                query: "",
                headers: &headers,
                payload_sha256: &payload,
            },
            example_time(),
        )
        .unwrap();
        assert!(value.ends_with(
            "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        ));
    }

    #[test]
    fn signs_the_aws_list_objects_example() {
        let headers = headers(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let value = authorization(
            ACCESS_KEY,
            &Zeroizing::new(SECRET_KEY.to_owned()),
            "us-east-1",
            &CanonicalRequest {
                method: "GET",
                path: "/",
                query: "max-keys=2&prefix=J",
                headers: &headers,
                payload_sha256: EMPTY_PAYLOAD_SHA256,
            },
            example_time(),
        )
        .unwrap();
        assert!(value.ends_with(
            "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        ));
    }

    #[test]
    fn uri_encoding_keeps_only_unreserved_bytes() {
        assert_eq!(uri_encode("a b/c~d$é", true), "a%20b/c~d%24%C3%A9");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
    }
}
