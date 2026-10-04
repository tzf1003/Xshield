//! Canonical bytes of the authenticated control-to-edge channel.
//!
//! The control plane and the edge sign and verify the same messages with the
//! deployment's shared HMAC key. Each binary keeps its own HMAC call; this
//! module owns only what both sides must agree on byte for byte: header names,
//! the replay window and the exact messages that are signed. Every message
//! starts with a label of its own, so a signature made for one purpose can
//! never be presented for another (an apply request signs a JSON document,
//! which cannot begin with either label).

/// Header carrying the lowercase hex HMAC of an apply request body, and of the
/// health request message.
pub const APPLY_SIGNATURE_HEADER: &str = "x-xshield-apply-signature";
/// Header on a successful apply response carrying the lowercase hex HMAC of
/// the acknowledgement, bound to the request it answers.
pub const APPLY_ACK_SIGNATURE_HEADER: &str = "x-xshield-apply-ack-signature";
/// Health request header: unix seconds when the control plane signed it.
pub const HEALTH_TIMESTAMP_HEADER: &str = "x-xshield-health-timestamp";
/// Health request header: 128 random bits as 32 lowercase hex characters.
pub const HEALTH_NONCE_HEADER: &str = "x-xshield-health-nonce";
/// How far a health request's timestamp may differ from the edge clock, in
/// either direction. A request is also remembered for twice this long, which
/// is the longest it could still be accepted.
pub const HEALTH_WINDOW_SECS: u64 = 30;
/// Random bytes in a health nonce.
pub const HEALTH_NONCE_BYTES: usize = 16;
/// Longest acknowledgement body either side will sign or verify. A real one
/// is about 150 bytes; the bound keeps verification cheap.
pub const APPLY_ACK_BODY_MAX: usize = 4096;

const HEALTH_LABEL: &[u8] = b"xshield-edge-health-v2";
const ACK_LABEL: &[u8] = b"xshield-edge-apply-ack-v1";

/// The bytes the control plane signs for one health request. The fields have
/// fixed shapes (decimal digits, 32 hex characters), so the newline joins are
/// unambiguous.
#[must_use]
pub fn health_message(timestamp_unix: u64, nonce_hex: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEALTH_LABEL.len() + 2 + 20 + nonce_hex.len());
    message.extend_from_slice(HEALTH_LABEL);
    message.push(b'\n');
    message.extend_from_slice(timestamp_unix.to_string().as_bytes());
    message.push(b'\n');
    message.extend_from_slice(nonce_hex.as_bytes());
    message
}

/// The bytes the edge signs for one acknowledgement. Binding the signature of
/// the request it answers means an acknowledgement captured for one apply
/// cannot be presented as the answer to another; the body comes last so the
/// fixed-length request signature keeps the encoding unambiguous.
#[must_use]
pub fn apply_ack_message(request_signature_hex: &str, ack_body: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(ACK_LABEL.len() + 2 + request_signature_hex.len() + ack_body.len());
    message.extend_from_slice(ACK_LABEL);
    message.push(b'\n');
    message.extend_from_slice(request_signature_hex.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(ack_body);
    message
}

/// Parses a health timestamp header. Only the canonical decimal form is
/// accepted (no sign, no leading zeros, no whitespace), so one instant has one
/// textual form.
#[must_use]
pub fn parse_health_timestamp(value: &str) -> Option<u64> {
    let canonical = !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    if !canonical {
        return None;
    }
    value.parse().ok()
}

/// Whether a health nonce header is exactly 32 lowercase hex characters.
#[must_use]
pub fn is_health_nonce(value: &str) -> bool {
    value.len() == HEALTH_NONCE_BYTES * 2
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_and_ack_messages_are_pinned_byte_for_byte() {
        assert_eq!(
            health_message(1_700_000_000, "0f1e2d3c4b5a69788796a5b4c3d2e1f0"),
            b"xshield-edge-health-v2\n1700000000\n0f1e2d3c4b5a69788796a5b4c3d2e1f0"
        );
        assert_eq!(
            apply_ack_message("ab", b"{}"),
            b"xshield-edge-apply-ack-v1\nab\n{}"
        );
    }

    #[test]
    fn labels_keep_purposes_apart() {
        let health = health_message(1, "00000000000000000000000000000000");
        let ack = apply_ack_message("", b"");
        assert!(!health.starts_with(ACK_LABEL));
        assert!(!ack.starts_with(HEALTH_LABEL));
        // An apply request body is a JSON object and never starts with a label.
        assert!(!health.starts_with(b"{"));
        assert!(!ack.starts_with(b"{"));
    }

    #[test]
    fn timestamps_have_exactly_one_textual_form() {
        assert_eq!(parse_health_timestamp("0"), Some(0));
        assert_eq!(parse_health_timestamp("1700000000"), Some(1_700_000_000));
        assert_eq!(
            parse_health_timestamp("18446744073709551615"),
            Some(u64::MAX)
        );
        for bad in [
            "",
            "+1",
            "-1",
            "01",
            "00",
            " 1",
            "1 ",
            "1.0",
            "1e3",
            "0x10",
            "18446744073709551616",
            "123456789012345678901",
            "１２３",
        ] {
            assert_eq!(parse_health_timestamp(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn nonces_are_exactly_32_lowercase_hex_characters() {
        assert!(is_health_nonce("0f1e2d3c4b5a69788796a5b4c3d2e1f0"));
        for bad in [
            "",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00",
            "0F1E2D3C4B5A69788796A5B4C3D2E1F0",
            "0f1e2d3c4b5a69788796a5b4c3d2e1g0",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f ",
        ] {
            assert!(!is_health_nonce(bad), "{bad:?}");
        }
    }
}
