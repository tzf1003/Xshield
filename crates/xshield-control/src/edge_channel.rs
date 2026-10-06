//! Control-side halves of the authenticated edge channel.
//!
//! Header names and the signed messages come from `xshield_core::edge_channel`,
//! which the edge shares, so both sides sign and verify the same bytes. The
//! HMAC key stays inside [`crate::EdgeApplyClient`], the only caller.

use openssl::{hash::MessageDigest, pkey::PKey, rand::rand_bytes, sign::Signer};
use reqwest::header::HeaderMap;
use std::{
    fmt::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};
use xshield_core::constant_time;
use xshield_core::edge_channel::{
    APPLY_ACK_BODY_MAX, APPLY_ACK_SIGNATURE_HEADER, HEALTH_NONCE_BYTES, apply_ack_message,
    health_message,
};

/// The edge's answer is not authentically its answer to this request: missing,
/// repeated or malformed signature, wrong key, another request, or other bytes.
const ACK_SIGNATURE_INVALID: &str = "EDGE_APPLY_ACK_SIGNATURE_INVALID";

/// The three header values of one signed health request.
pub(crate) struct HealthAuth {
    pub(crate) timestamp: String,
    pub(crate) nonce: String,
    pub(crate) signature: String,
}

/// Signs a health request with the current time and a fresh random nonce, so
/// a captured request is useless once its window has passed and can never be
/// presented twice inside it. `None` only when the system clock or the
/// crypto library fails; the caller then reports the edge as unreachable
/// instead of sending an unprotected request.
pub(crate) fn sign_health_request(key: &[u8; 32]) -> Option<HealthAuth> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let mut nonce = [0_u8; HEALTH_NONCE_BYTES];
    rand_bytes(&mut nonce).ok()?;
    sign_health(key, timestamp, &lower_hex(&nonce))
}

fn sign_health(key: &[u8; 32], timestamp: u64, nonce_hex: &str) -> Option<HealthAuth> {
    let signature = lower_hex(&hmac(key, &health_message(timestamp, nonce_hex))?);
    Some(HealthAuth {
        timestamp: timestamp.to_string(),
        nonce: nonce_hex.to_owned(),
        signature,
    })
}

/// Checks that `body` is exactly what the edge signed as its answer to the
/// request whose signature was `request_signature_hex`. The signature is
/// verified over the raw bytes before anything is parsed.
///
/// # Errors
/// `EDGE_APPLY_ACK_INVALID` for an oversized body and
/// `EDGE_APPLY_ACK_SIGNATURE_INVALID` for every authentication failure.
pub(crate) fn verify_apply_ack(
    key: &[u8; 32],
    request_signature_hex: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), &'static str> {
    if body.len() > APPLY_ACK_BODY_MAX {
        return Err("EDGE_APPLY_ACK_INVALID");
    }
    let mut values = headers.get_all(APPLY_ACK_SIGNATURE_HEADER).iter();
    let presented = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .and_then(decode_signature)
        .ok_or(ACK_SIGNATURE_INVALID)?;
    let expected =
        hmac(key, &apply_ack_message(request_signature_hex, body)).ok_or(ACK_SIGNATURE_INVALID)?;
    // A length mismatch is a refusal (the helper returns false), never a panic on a
    // network-supplied value.
    if constant_time::eq(&expected, &presented) {
        Ok(())
    } else {
        Err(ACK_SIGNATURE_INVALID)
    }
}

fn hmac(key: &[u8; 32], message: &[u8]) -> Option<Vec<u8>> {
    let key = PKey::hmac(key).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
    signer.update(message).ok()?;
    signer.sign_to_vec().ok()
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Exactly 64 lowercase hex characters, the form the edge emits.
fn decode_signature(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        _ => byte - b'a' + 10,
    };
    Some(
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use crate::site_config::EdgeApplyClient;
    use axum::{
        Json, Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };
    use xshield_core::{
        GatewayApplyAck, GatewayApplyRequest,
        edge_channel::{
            APPLY_ACK_SIGNATURE_HEADER, APPLY_SIGNATURE_HEADER, HEALTH_NONCE_HEADER,
            HEALTH_TIMESTAMP_HEADER, apply_ack_message, health_message, is_health_nonce,
            parse_health_timestamp,
        },
    };

    const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER_KEY_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn key_of(hex: &str) -> [u8; 32] {
        let mut key = [0_u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        key
    }

    fn hmac_hex(key: &[u8; 32], message: &[u8]) -> String {
        let key = PKey::hmac(key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(message).unwrap();
        super::lower_hex(&signer.sign_to_vec().unwrap())
    }

    /// How the stand-in edge answers an apply.
    #[derive(Clone, Copy, Debug)]
    enum Ack {
        /// What an edge from before the fix returns: a valid ack, no signature.
        Unsigned,
        Signed,
        SignedWithAnotherKey,
        /// Signed for a different request: a replay of another apply's ack.
        SignedForAnotherRequest,
        /// Signed, then re-serialized with one extra space: same meaning, other bytes.
        SignedThenReformatted,
        NotHex,
        UppercaseHex,
        TwoSignatures,
        /// Correctly signed, but acknowledging a different apply.
        SignedForAnotherApplyId,
        /// An unsigned refusal with this status and body, as the edge sends.
        Refused(u16, &'static str),
    }

    struct Edge {
        ack: Ack,
        health_requests: Mutex<Vec<HeaderMap>>,
    }

    async fn apply_endpoint(
        State(edge): State<Arc<Edge>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        if let Ack::Refused(status, body) = edge.ack {
            return (
                StatusCode::from_u16(status).unwrap(),
                [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
                body,
            )
                .into_response();
        }
        let request_signature = headers
            .get(APPLY_SIGNATURE_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let request: GatewayApplyRequest = serde_json::from_slice(&body).unwrap();
        let ack = GatewayApplyAck {
            apply_id: if matches!(edge.ack, Ack::SignedForAnotherApplyId) {
                "apply_other".to_owned()
            } else {
                request.apply_id
            },
            active_revision: request.snapshot_revision,
            apply_state: "active".to_owned(),
            reason_code: "EDGE_APPLY_CONFIRMED".to_owned(),
        };
        let ack_body = serde_json::to_vec(&ack).unwrap();
        let sign = |key_hex: &str, request_signature: &str| {
            hmac_hex(
                &key_of(key_hex),
                &apply_ack_message(request_signature, &ack_body),
            )
        };
        let name = HeaderName::from_static(APPLY_ACK_SIGNATURE_HEADER);
        let mut response_headers = HeaderMap::new();
        response_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut sent = ack_body.clone();
        let mut put = |value: String| {
            response_headers.append(name.clone(), HeaderValue::from_str(&value).unwrap());
        };
        match edge.ack {
            Ack::Unsigned => {}
            Ack::Signed | Ack::SignedForAnotherApplyId => put(sign(KEY_HEX, &request_signature)),
            Ack::SignedWithAnotherKey => put(sign(OTHER_KEY_HEX, &request_signature)),
            Ack::SignedForAnotherRequest => put(sign(KEY_HEX, &"cd".repeat(32))),
            Ack::SignedThenReformatted => {
                put(sign(KEY_HEX, &request_signature));
                sent = String::from_utf8(ack_body.clone())
                    .unwrap()
                    .replacen("\"active_revision\":", "\"active_revision\": ", 1)
                    .into_bytes();
            }
            Ack::NotHex => put("not-hex".to_owned()),
            Ack::UppercaseHex => put(sign(KEY_HEX, &request_signature).to_uppercase()),
            Ack::TwoSignatures => {
                put(sign(KEY_HEX, &request_signature));
                put(sign(KEY_HEX, &request_signature));
            }
            Ack::Refused(..) => unreachable!("answered before the acknowledgement is built"),
        }
        (StatusCode::OK, response_headers, sent).into_response()
    }

    async fn health_endpoint(State(edge): State<Arc<Edge>>, headers: HeaderMap) -> Response {
        edge.health_requests.lock().unwrap().push(headers);
        Json(serde_json::json!({ "edge_state": "healthy" })).into_response()
    }

    async fn edge(ack: Ack) -> (EdgeApplyClient, Arc<Edge>) {
        let edge = Arc::new(Edge {
            ack,
            health_requests: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route("/internal/v1/apply", post(apply_endpoint))
            .route("/internal/v1/health", get(health_endpoint))
            .with_state(Arc::clone(&edge));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let client =
            EdgeApplyClient::new(format!("http://{address}/internal/v1/apply"), KEY_HEX).unwrap();
        (client, edge)
    }

    // Independent HMAC-SHA256 values computed with Python's `hmac` module over
    // the messages documented in `xshield_core::edge_channel`. The edge pins
    // the same literals from its side, so the two implementations cannot drift
    // apart without one of the suites failing.
    const VECTOR_KEY_HEX: &str = KEY_HEX;
    const VECTOR_NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const HEALTH_VECTOR: &str = "c8c965a422624313617198e566a4e8681702fc688086f0818a9a014efb3a3da7";
    const ACK_VECTOR: &str = "0611268a882723b00c849321661f8020d1c627074fd8031173a5420415e2e5f3";
    const ACK_VECTOR_BODY: &[u8] = br#"{"apply_id":"apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01","active_revision":7,"apply_state":"active","reason_code":"EDGE_APPLY_CONFIRMED"}"#;

    fn ack_headers(signature: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(APPLY_ACK_SIGNATURE_HEADER),
            HeaderValue::from_str(signature).unwrap(),
        );
        headers
    }

    #[test]
    fn signatures_match_the_vectors_the_edge_pins_from_its_side() {
        let key = key_of(VECTOR_KEY_HEX);
        let auth = super::sign_health(&key, 1_700_000_000, VECTOR_NONCE).unwrap();
        assert_eq!(auth.timestamp, "1700000000");
        assert_eq!(auth.nonce, VECTOR_NONCE);
        assert_eq!(auth.signature, HEALTH_VECTOR);
        assert_eq!(
            super::verify_apply_ack(
                &key,
                &"ab".repeat(32),
                &ack_headers(ACK_VECTOR),
                ACK_VECTOR_BODY
            ),
            Ok(())
        );
    }

    #[test]
    fn the_ack_check_binds_key_request_and_every_byte_of_the_body() {
        let key = key_of(VECTOR_KEY_HEX);
        let request_signature = "ab".repeat(32);
        let headers = ack_headers(ACK_VECTOR);
        let verify = |key: &[u8; 32], request: &str, headers: &HeaderMap, body: &[u8]| {
            super::verify_apply_ack(key, request, headers, body)
        };
        assert_eq!(
            verify(&key, &request_signature, &headers, ACK_VECTOR_BODY),
            Ok(())
        );
        // Another key, another request, a missing or empty header.
        let other = key_of(OTHER_KEY_HEX);
        for (name, result) in [
            (
                "wrong key",
                verify(&other, &request_signature, &headers, ACK_VECTOR_BODY),
            ),
            (
                "another request",
                verify(&key, &"cd".repeat(32), &headers, ACK_VECTOR_BODY),
            ),
            (
                "no header",
                verify(&key, &request_signature, &HeaderMap::new(), ACK_VECTOR_BODY),
            ),
            (
                "empty header",
                verify(&key, &request_signature, &ack_headers(""), ACK_VECTOR_BODY),
            ),
            (
                "short signature",
                verify(
                    &key,
                    &request_signature,
                    &ack_headers(&ACK_VECTOR[..62]),
                    ACK_VECTOR_BODY,
                ),
            ),
            (
                "long signature",
                verify(
                    &key,
                    &request_signature,
                    &ack_headers(&format!("{ACK_VECTOR}00")),
                    ACK_VECTOR_BODY,
                ),
            ),
        ] {
            assert_eq!(result, Err("EDGE_APPLY_ACK_SIGNATURE_INVALID"), "{name}");
        }
        // Flipping any single byte of the body breaks the signature.
        for index in 0..ACK_VECTOR_BODY.len() {
            let mut tampered = ACK_VECTOR_BODY.to_vec();
            tampered[index] ^= 0x01;
            assert_eq!(
                verify(&key, &request_signature, &headers, &tampered),
                Err("EDGE_APPLY_ACK_SIGNATURE_INVALID"),
                "byte {index}"
            );
        }
        // Oversized bodies are refused before any HMAC work.
        let oversized = vec![b' '; xshield_core::edge_channel::APPLY_ACK_BODY_MAX + 1];
        assert_eq!(
            verify(&key, &request_signature, &headers, &oversized),
            Err("EDGE_APPLY_ACK_INVALID")
        );
    }

    fn request() -> GatewayApplyRequest {
        GatewayApplyRequest {
            protocol_version: 1,
            tenant_id: "tenant_a".to_owned(),
            apply_id: "apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01".to_owned(),
            snapshot_revision: 7,
            sites: Vec::new(),
        }
    }

    fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
        headers
            .get(name)
            .unwrap_or_else(|| panic!("missing header {name}"))
            .to_str()
            .unwrap()
    }

    // Reviewer finding: the edge's answer to an apply was plain JSON, so
    // whoever sat between the control plane and the edge (or any process able
    // to answer on that port) could say "active" without the edge having
    // applied anything, and the control plane would mark the revision active.
    #[tokio::test]
    async fn an_apply_acknowledgement_without_a_valid_signature_is_refused() {
        for ack in [
            Ack::Unsigned,
            Ack::SignedWithAnotherKey,
            Ack::SignedForAnotherRequest,
            Ack::SignedThenReformatted,
            Ack::NotHex,
            Ack::UppercaseHex,
            Ack::TwoSignatures,
        ] {
            let (client, _edge) = edge(ack).await;
            assert_eq!(
                client
                    .apply(&request())
                    .await
                    .map(|_| ())
                    .map_err(|refusal| refusal.reason),
                Err("EDGE_APPLY_ACK_SIGNATURE_INVALID"),
                "{ack:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_signed_acknowledgement_is_accepted_and_its_content_is_still_checked() {
        let (client, _edge) = edge(Ack::Signed).await;
        let ack = client.apply(&request()).await.unwrap();
        assert_eq!(ack.active_revision, 7);
        assert_eq!(ack.reason_code, "EDGE_APPLY_CONFIRMED");

        // A genuine signature does not excuse an ack for another apply.
        let (client, _edge) = edge(Ack::SignedForAnotherApplyId).await;
        assert_eq!(
            client
                .apply(&request())
                .await
                .map(|_| ())
                .map_err(|refusal| refusal.reason),
            Err("EDGE_APPLY_ACK_INVALID")
        );
    }

    // The edge refuses a snapshot whose page-issuing site cannot have its
    // action descriptors supplied, naming that site. The control plane keeps
    // the two stable reasons (its apply state and the console explain them)
    // and still turns any code it does not know into the generic refusal.
    // Only a conflict keeps the named site, and only a valid site ID: the
    // name decides which site's status carries the failure, nothing more.
    #[tokio::test]
    async fn descriptor_supply_refusals_keep_their_stable_reasons() {
        let site_b = Some(xshield_core::domain::SiteId::parse("site_b").unwrap());
        for (ack, expected, named) in [
            (
                Ack::Refused(
                    409,
                    r#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_DESCRIPTOR_CONFLICT","site_id":"site_b"}"#,
                ),
                "EDGE_APPLY_DESCRIPTOR_CONFLICT",
                site_b,
            ),
            (
                Ack::Refused(
                    409,
                    r#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_DESCRIPTOR_CONFLICT","site_id":"not a site"}"#,
                ),
                "EDGE_APPLY_DESCRIPTOR_CONFLICT",
                None,
            ),
            (
                Ack::Refused(
                    503,
                    r#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_DESCRIPTOR_UNAVAILABLE","site_id":"site_a"}"#,
                ),
                "EDGE_APPLY_DESCRIPTOR_UNAVAILABLE",
                None,
            ),
            (
                Ack::Refused(
                    409,
                    r#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_STALE_REVISION","site_id":"site_b"}"#,
                ),
                "EDGE_APPLY_STALE_REVISION",
                None,
            ),
            (
                Ack::Refused(
                    409,
                    r#"{"error":"edge_apply_failed","reason_code":"EDGE_APPLY_NOT_A_KNOWN_REASON"}"#,
                ),
                "EDGE_APPLY_REJECTED",
                None,
            ),
            (Ack::Refused(503, "not json"), "EDGE_APPLY_REJECTED", None),
        ] {
            let (client, _edge) = edge(ack).await;
            let refusal = client.apply(&request()).await.unwrap_err();
            assert_eq!(
                (refusal.reason, refusal.site_id),
                (expected, named),
                "{ack:?}"
            );
        }
    }

    // Reviewer finding: the health request signed the constant `health-v1`, so
    // one captured request stayed valid forever and could be replayed at will.
    #[tokio::test]
    async fn every_health_request_carries_a_fresh_timestamp_and_nonce_bound_into_its_signature() {
        let (client, edge) = edge(Ack::Signed).await;
        client.health().await.unwrap();
        client.health().await.unwrap();
        let seen = edge.health_requests.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut nonces = BTreeSet::new();
        let mut signatures = BTreeSet::new();
        for headers in seen.iter() {
            let timestamp = parse_health_timestamp(header(headers, HEALTH_TIMESTAMP_HEADER))
                .expect("a canonical timestamp");
            assert!(timestamp.abs_diff(now) <= 5, "{timestamp} vs {now}");
            let nonce = header(headers, HEALTH_NONCE_HEADER);
            assert!(is_health_nonce(nonce), "{nonce}");
            let signature = header(headers, APPLY_SIGNATURE_HEADER);
            assert_eq!(
                signature,
                hmac_hex(&key_of(KEY_HEX), &health_message(timestamp, nonce))
            );
            nonces.insert(nonce.to_owned());
            signatures.insert(signature.to_owned());
        }
        assert_eq!(nonces.len(), 2, "a nonce must never repeat");
        assert_eq!(signatures.len(), 2, "so no two requests share a signature");
    }
}
