//! Replay protection for the signed edge health request.
//!
//! The control plane signs each health request over a fresh timestamp and a
//! random nonce (the messages are defined once, in `xshield_core::edge_channel`).
//! The edge refuses a request whose signature does not verify, whose timestamp
//! is outside the window, or whose nonce it has already seen inside that
//! window. Only requests that authenticate are remembered, so a caller without
//! the key cannot use up the cache.

use crate::apply_api::{decode_hex, error, sign};
use axum::{http::HeaderMap, http::StatusCode, response::Response};
use openssl::memcmp;
use std::{
    collections::{HashSet, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};
use xshield_core::edge_channel::{
    APPLY_SIGNATURE_HEADER, HEALTH_NONCE_BYTES, HEALTH_NONCE_HEADER, HEALTH_TIMESTAMP_HEADER,
    HEALTH_WINDOW_SECS, health_message, is_health_nonce, parse_health_timestamp,
};

/// Distinct nonces remembered at once. A control plane polls health a few
/// times a second at most. A full cache refuses new requests instead of
/// forgetting a nonce, because a forgotten nonce could be replayed.
const NONCES_MAX: usize = 4_096;
/// How long a nonce is remembered: a request's timestamp may be a full window
/// ahead of the edge clock when it is first used and stays acceptable for a
/// full window after that, plus a margin for the monotonic and wall clocks.
const RETENTION: Duration = Duration::from_secs(2 * HEALTH_WINDOW_SECS + 5);

/// Why a health request was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HealthRefusal {
    /// Missing, repeated or malformed headers, or a signature that does not
    /// verify. Nothing about the request is revealed beyond this.
    Unauthenticated,
    /// Correctly signed, but the timestamp is outside the window.
    Expired,
    /// Correctly signed and in the window, but the nonce was already used.
    Replayed,
    /// Correctly signed, but the cache holds as many unexpired nonces as it may.
    Busy,
    /// The signature could not be computed at all.
    Unavailable,
}

impl HealthRefusal {
    /// The HTTP answer. Refusals other than `Unauthenticated` are reached only
    /// with a valid signature, so they tell a key holder why and nobody else.
    pub(crate) fn response(self) -> Response {
        match self {
            Self::Unauthenticated => {
                error(StatusCode::UNAUTHORIZED, "EDGE_APPLY_SIGNATURE_INVALID")
            }
            Self::Expired => error(StatusCode::UNAUTHORIZED, "EDGE_HEALTH_REQUEST_EXPIRED"),
            Self::Replayed => error(StatusCode::UNAUTHORIZED, "EDGE_HEALTH_REQUEST_REPLAYED"),
            Self::Busy => error(StatusCode::TOO_MANY_REQUESTS, "EDGE_HEALTH_RATE_LIMITED"),
            Self::Unavailable => error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "EDGE_APPLY_SIGNATURE_UNAVAILABLE",
            ),
        }
    }
}

/// Authenticates health requests and refuses replays.
pub(crate) struct HealthGate {
    key: [u8; 32],
    seen: Mutex<NonceCache>,
}

impl HealthGate {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            seen: Mutex::new(NonceCache::default()),
        }
    }

    /// Admits one health request. `now_unix` is the wall clock, which the
    /// request's timestamp is compared with; `now` is the monotonic clock that
    /// ages remembered nonces.
    ///
    /// # Errors
    /// A [`HealthRefusal`] naming the first check that failed. The signature is
    /// verified before the window, and the window before the nonce is
    /// recorded, so only authentic and current requests occupy the cache.
    pub(crate) fn check(
        &self,
        headers: &HeaderMap,
        now_unix: u64,
        now: Instant,
    ) -> Result<(), HealthRefusal> {
        let signature = single(headers, APPLY_SIGNATURE_HEADER)
            .and_then(decode_hex)
            .ok_or(HealthRefusal::Unauthenticated)?;
        let timestamp = single(headers, HEALTH_TIMESTAMP_HEADER)
            .and_then(parse_health_timestamp)
            .ok_or(HealthRefusal::Unauthenticated)?;
        let nonce = single(headers, HEALTH_NONCE_HEADER)
            .filter(|value| is_health_nonce(value))
            .ok_or(HealthRefusal::Unauthenticated)?;
        let expected =
            sign(&self.key, &health_message(timestamp, nonce)).ok_or(HealthRefusal::Unavailable)?;
        // `memcmp::eq` requires equal lengths; a mismatch is a refusal.
        if expected.len() != signature.len() || !memcmp::eq(&expected, &signature) {
            return Err(HealthRefusal::Unauthenticated);
        }
        if timestamp.abs_diff(now_unix) > HEALTH_WINDOW_SECS {
            return Err(HealthRefusal::Expired);
        }
        let nonce = nonce_bytes(nonce).ok_or(HealthRefusal::Unauthenticated)?;
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admit(nonce, now)
    }
}

/// The header's only value, if it has exactly one and it is text.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
}

fn nonce_bytes(hex: &str) -> Option<[u8; HEALTH_NONCE_BYTES]> {
    let mut bytes = [0_u8; HEALTH_NONCE_BYTES];
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    if hex.len() != HEALTH_NONCE_BYTES * 2 {
        return None;
    }
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (slot, pair) in bytes.iter_mut().zip(pairs) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(bytes)
}

/// Nonces seen inside the retention period, oldest first. Insertion order is
/// age order because the caller's clock is monotonic, so expiry only ever
/// looks at the front and each call is amortized constant time.
#[derive(Default)]
struct NonceCache {
    order: VecDeque<(Instant, [u8; HEALTH_NONCE_BYTES])>,
    seen: HashSet<[u8; HEALTH_NONCE_BYTES]>,
}

impl NonceCache {
    fn admit(
        &mut self,
        nonce: [u8; HEALTH_NONCE_BYTES],
        now: Instant,
    ) -> Result<(), HealthRefusal> {
        while let Some(&(at, oldest)) = self.order.front() {
            if now.saturating_duration_since(at) < RETENTION {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&oldest);
        }
        if self.seen.contains(&nonce) {
            return Err(HealthRefusal::Replayed);
        }
        if self.order.len() >= NONCES_MAX {
            return Err(HealthRefusal::Busy);
        }
        self.order.push_back((now, nonce));
        self.seen.insert(nonce);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const KEY: [u8; 32] = [7_u8; 32];
    const NONCE: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const NOW: u64 = 1_700_000_000;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut output, byte| {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
            output
        })
    }

    fn headers(key: &[u8; 32], timestamp: u64, nonce: &str) -> HeaderMap {
        let signature = hex(&sign(key, &health_message(timestamp, nonce)).unwrap());
        let mut headers = HeaderMap::new();
        for (name, value) in [
            (APPLY_SIGNATURE_HEADER, signature),
            (HEALTH_TIMESTAMP_HEADER, timestamp.to_string()),
            (HEALTH_NONCE_HEADER, nonce.to_owned()),
        ] {
            headers.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        headers
    }

    fn nonce_n(index: usize) -> String {
        format!("{index:032x}")
    }

    #[test]
    fn a_signed_request_is_accepted_once_and_its_replay_is_refused() {
        let gate = HealthGate::new(KEY);
        let now = Instant::now();
        let request = headers(&KEY, NOW, NONCE);
        assert_eq!(gate.check(&request, NOW, now), Ok(()));
        assert_eq!(
            gate.check(&request, NOW, now),
            Err(HealthRefusal::Replayed),
            "the same bytes presented again"
        );
        assert_eq!(
            gate.check(&request, NOW + 20, now + Duration::from_secs(20)),
            Err(HealthRefusal::Replayed),
            "and again later inside the window"
        );
        assert_eq!(
            gate.check(&headers(&KEY, NOW, &nonce_n(1)), NOW, now),
            Ok(()),
            "a new nonce is a new request"
        );
    }

    #[test]
    fn the_constant_signature_request_of_the_old_control_client_is_refused() {
        let gate = HealthGate::new(KEY);
        let mut legacy = HeaderMap::new();
        legacy.insert(
            APPLY_SIGNATURE_HEADER,
            HeaderValue::from_str(&hex(&sign(&KEY, b"health-v1").unwrap())).unwrap(),
        );
        assert_eq!(
            gate.check(&legacy, NOW, Instant::now()),
            Err(HealthRefusal::Unauthenticated)
        );
    }

    #[test]
    fn the_window_is_thirty_seconds_in_both_directions() {
        let now = Instant::now();
        for (offset, accepted) in [
            (-30_i64, true),
            (-31, false),
            (30, true),
            (31, false),
            (0, true),
        ] {
            let gate = HealthGate::new(KEY);
            let timestamp = NOW.checked_add_signed(offset).unwrap();
            let verdict = gate.check(&headers(&KEY, timestamp, NONCE), NOW, now);
            if accepted {
                assert_eq!(verdict, Ok(()), "offset {offset}");
            } else {
                assert_eq!(verdict, Err(HealthRefusal::Expired), "offset {offset}");
            }
        }
        // An unreadable wall clock reads as 0, which is outside every window:
        // a broken clock refuses requests instead of accepting stale ones.
        let gate = HealthGate::new(KEY);
        assert_eq!(
            gate.check(&headers(&KEY, NOW, NONCE), 0, now),
            Err(HealthRefusal::Expired)
        );
    }

    #[test]
    fn the_signature_covers_the_key_the_timestamp_and_the_nonce() {
        let gate = HealthGate::new(KEY);
        let now = Instant::now();
        let other_key = [8_u8; 32];
        assert_eq!(
            gate.check(&headers(&other_key, NOW, NONCE), NOW, now),
            Err(HealthRefusal::Unauthenticated)
        );
        // Re-labelling a signed request with another timestamp or nonce.
        let mut moved = headers(&KEY, NOW, NONCE);
        moved.insert(
            HEALTH_TIMESTAMP_HEADER,
            HeaderValue::from_str(&(NOW + 1).to_string()).unwrap(),
        );
        assert_eq!(
            gate.check(&moved, NOW, now),
            Err(HealthRefusal::Unauthenticated)
        );
        let mut renonced = headers(&KEY, NOW, NONCE);
        renonced.insert(
            HEALTH_NONCE_HEADER,
            HeaderValue::from_str(&nonce_n(9)).unwrap(),
        );
        assert_eq!(
            gate.check(&renonced, NOW, now),
            Err(HealthRefusal::Unauthenticated)
        );
        // The apply-body signature of the same key is not a health signature.
        let mut cross = headers(&KEY, NOW, NONCE);
        cross.insert(
            APPLY_SIGNATURE_HEADER,
            HeaderValue::from_str(&hex(&sign(&KEY, b"{}").unwrap())).unwrap(),
        );
        assert_eq!(
            gate.check(&cross, NOW, now),
            Err(HealthRefusal::Unauthenticated)
        );
    }

    #[test]
    fn missing_repeated_or_non_canonical_headers_are_unauthenticated() {
        let gate = HealthGate::new(KEY);
        let now = Instant::now();
        for name in [
            APPLY_SIGNATURE_HEADER,
            HEALTH_TIMESTAMP_HEADER,
            HEALTH_NONCE_HEADER,
        ] {
            let mut missing = headers(&KEY, NOW, NONCE);
            missing.remove(name);
            assert_eq!(
                gate.check(&missing, NOW, now),
                Err(HealthRefusal::Unauthenticated),
                "missing {name}"
            );
            let mut repeated = headers(&KEY, NOW, NONCE);
            let value = repeated.get(name).unwrap().clone();
            repeated.append(name, value);
            assert_eq!(
                gate.check(&repeated, NOW, now),
                Err(HealthRefusal::Unauthenticated),
                "repeated {name}"
            );
        }
        for (name, value) in [
            (HEALTH_TIMESTAMP_HEADER, format!("0{NOW}")),
            (HEALTH_TIMESTAMP_HEADER, format!("+{NOW}")),
            (HEALTH_TIMESTAMP_HEADER, format!("{NOW} ")),
            (HEALTH_NONCE_HEADER, NONCE.to_uppercase()),
            (HEALTH_NONCE_HEADER, NONCE[..30].to_owned()),
            (HEALTH_NONCE_HEADER, format!("{NONCE}00")),
        ] {
            let mut bad = headers(&KEY, NOW, NONCE);
            bad.insert(name, HeaderValue::from_str(&value).unwrap());
            assert_eq!(
                gate.check(&bad, NOW, now),
                Err(HealthRefusal::Unauthenticated),
                "{name}: {value:?}"
            );
        }
    }

    // Only requests that authenticate are remembered, so a caller without the
    // key cannot fill the cache and starve the control plane.
    #[test]
    fn unauthenticated_and_expired_requests_never_occupy_the_cache() {
        let gate = HealthGate::new(KEY);
        let now = Instant::now();
        let other_key = [8_u8; 32];
        for index in 0..NONCES_MAX + 10 {
            let _ = gate.check(&headers(&other_key, NOW, &nonce_n(index)), NOW, now);
            let _ = gate.check(&headers(&KEY, NOW - 600, &nonce_n(index)), NOW, now);
        }
        assert_eq!(gate.check(&headers(&KEY, NOW, NONCE), NOW, now), Ok(()));
    }

    #[test]
    fn a_full_cache_refuses_instead_of_forgetting_and_recovers_when_nonces_expire() {
        let gate = HealthGate::new(KEY);
        let start = Instant::now();
        for index in 0..NONCES_MAX {
            assert_eq!(
                gate.check(&headers(&KEY, NOW, &nonce_n(index)), NOW, start),
                Ok(())
            );
        }
        // Full: a new nonce is refused, and so is a replay of the oldest one.
        assert_eq!(
            gate.check(&headers(&KEY, NOW, &nonce_n(NONCES_MAX)), NOW, start),
            Err(HealthRefusal::Busy)
        );
        assert_eq!(
            gate.check(&headers(&KEY, NOW, &nonce_n(0)), NOW, start),
            Err(HealthRefusal::Replayed)
        );
        // Once the retention has passed the old nonces are forgotten (their
        // requests are long out of the window, so they stay unusable anyway).
        let later = start + RETENTION;
        assert_eq!(
            gate.check(
                &headers(&KEY, NOW + 60, &nonce_n(NONCES_MAX)),
                NOW + 60,
                later
            ),
            Ok(())
        );
        assert_eq!(
            gate.check(&headers(&KEY, NOW, &nonce_n(0)), NOW + 60, later),
            Err(HealthRefusal::Expired)
        );
    }

    // A nonce must outlive the last moment its request could still be accepted:
    // signed 30 seconds ahead of the edge clock, a request is acceptable until
    // the edge clock reaches timestamp + 30, which is 60 seconds after first use.
    #[test]
    fn a_nonce_is_remembered_for_as_long_as_its_request_could_be_replayed() {
        let gate = HealthGate::new(KEY);
        let start = Instant::now();
        let request = headers(&KEY, NOW + 30, NONCE);
        assert_eq!(gate.check(&request, NOW, start), Ok(()));
        assert_eq!(
            gate.check(&request, NOW + 60, start + Duration::from_mins(1)),
            Err(HealthRefusal::Replayed),
            "still inside the window, so the nonce must still be remembered"
        );
        assert_eq!(
            gate.check(&request, NOW + 61, start + Duration::from_secs(61)),
            Err(HealthRefusal::Expired),
            "outside the window it is refused for its age, not for its nonce"
        );
    }

    // The values below were computed independently with Python's `hmac`; the
    // control plane's test suite pins the same ones from its side.
    #[test]
    fn the_request_the_control_client_is_pinned_to_send_is_accepted() {
        let key = {
            let mut key = [0_u8; 32];
            for (index, pair) in "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .enumerate()
            {
                key[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
            key
        };
        let gate = HealthGate::new(key);
        let mut request = HeaderMap::new();
        for (name, value) in [
            (
                APPLY_SIGNATURE_HEADER,
                "c8c965a422624313617198e566a4e8681702fc688086f0818a9a014efb3a3da7",
            ),
            (HEALTH_TIMESTAMP_HEADER, "1700000000"),
            (HEALTH_NONCE_HEADER, NONCE),
        ] {
            request.insert(name, HeaderValue::from_static(value));
        }
        assert_eq!(gate.check(&request, 1_700_000_000, Instant::now()), Ok(()));
    }
}
