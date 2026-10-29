//! Minimal RFC 6455 server-side framing for the probe WSS channel.
//!
//! Only this gateway accepts connections on the reserved WSS path and only
//! the shipped sensor dials them (docs/07 7.3), so the server needs no
//! extension negotiation, no subprotocol, and no continuation frames: every
//! probe message is one complete, bounded text frame. Anything outside that
//! exact subset closes the connection instead of being interpreted.

use openssl::{
    base64::{decode_block, encode_block},
    sha::sha1,
};

/// One probe message, matching the bounded HTTPS batch cap (docs/07 7.3).
pub const MAX_WS_FRAME_BYTES: usize = 16 * 1024;
/// RFC 6455 handshake GUID.
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// A masked client frame header is at most 2 + 8 (extended length) + 4 (mask) bytes.
const MAX_HEADER_BYTES: usize = 14;
/// Control frame payloads (close/ping/pong) are capped by RFC 6455 itself.
const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;

/// Computes the `Sec-WebSocket-Accept` value for a validated client key.
#[must_use]
pub fn accept_key(sec_websocket_key: &str) -> String {
    let mut input = Vec::with_capacity(sec_websocket_key.len() + WEBSOCKET_GUID.len());
    input.extend_from_slice(sec_websocket_key.as_bytes());
    input.extend_from_slice(WEBSOCKET_GUID.as_bytes());
    encode_block(&sha1(&input))
}

/// Returns whether a `Sec-WebSocket-Key` value decodes to exactly 16 bytes,
/// the only shape RFC 6455 allows.
#[must_use]
pub fn valid_websocket_key(value: &str) -> bool {
    value.is_ascii() && decode_block(value).is_ok_and(|bytes| bytes.len() == 16)
}

/// A kind of malformed or out-of-subset frame, each with its own close code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WsProtocolError {
    /// Unmasked client frame, reserved bits set, continuation frame, or any
    /// other shape outside the exact accepted subset.
    Protocol,
    /// A data frame payload beyond [`MAX_WS_FRAME_BYTES`], or a control frame
    /// payload beyond 125 bytes.
    TooLarge,
    /// A text frame whose payload is not valid UTF-8.
    InvalidUtf8,
}

impl WsProtocolError {
    /// Returns the RFC 6455 close code for this refusal.
    #[must_use]
    pub const fn close_code(self) -> u16 {
        match self {
            Self::Protocol => 1002,
            Self::TooLarge => 1009,
            Self::InvalidUtf8 => 1007,
        }
    }
}

/// A validated, unmasked frame opcode within the accepted subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WsOpcode {
    /// A UTF-8 text message: one probe observation batch.
    Text,
    /// A binary message; the probe never sends one, so this always closes.
    Binary,
    /// A close handshake frame.
    Close,
    /// A ping; the gateway answers with a pong carrying the same payload.
    Ping,
    /// An unsolicited pong.
    Pong,
}

/// One fully parsed, unmasked client frame and the bytes it consumed.
#[derive(Debug, Eq, PartialEq)]
pub struct ParsedFrame {
    /// The frame's opcode.
    pub opcode: WsOpcode,
    /// The unmasked payload.
    pub payload: Vec<u8>,
    /// Bytes of `buf` this frame consumed; the caller drains exactly this many.
    pub consumed: usize,
}

/// Parses at most one complete frame from the front of `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet hold a complete frame (the
/// caller should read more bytes and retry). Never buffers an oversized
/// payload: the length is validated before the payload bytes are required.
///
/// # Errors
/// Returns [`WsProtocolError`] for anything outside the exact accepted
/// subset: a continuation frame, an unmasked client frame, reserved bits,
/// an unknown opcode, or a frame beyond the size bound for its kind.
pub fn parse_frame(buf: &[u8]) -> Result<Option<ParsedFrame>, WsProtocolError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let first = buf[0];
    let second = buf[1];
    let fin = first & 0x80 != 0;
    let reserved = first & 0x70;
    let opcode_bits = first & 0x0f;
    let masked = second & 0x80 != 0;
    let length_bits = second & 0x7f;
    if reserved != 0 || !masked {
        return Err(WsProtocolError::Protocol);
    }
    let (payload_len, length_field_bytes): (usize, usize) = match length_bits {
        0..=125 => (usize::from(length_bits), 0),
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (usize::from(u16::from_be_bytes([buf[2], buf[3]])), 2)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[2..10]);
            let value = u64::from_be_bytes(raw);
            let Ok(value) = usize::try_from(value) else {
                return Err(WsProtocolError::TooLarge);
            };
            (value, 8)
        }
        _ => unreachable!("7-bit field"),
    };
    let opcode = match opcode_bits {
        0x1 => WsOpcode::Text,
        0x2 => WsOpcode::Binary,
        0x8 => WsOpcode::Close,
        0x9 => WsOpcode::Ping,
        0xA => WsOpcode::Pong,
        // Continuation (0x0) is never valid: every probe message is one
        // complete frame. Opcodes 0x3-0x7 and 0xB-0xF are reserved.
        _ => return Err(WsProtocolError::Protocol),
    };
    let is_control = matches!(opcode, WsOpcode::Close | WsOpcode::Ping | WsOpcode::Pong);
    if !fin || (is_control && payload_len > MAX_CONTROL_PAYLOAD_BYTES) {
        return Err(WsProtocolError::Protocol);
    }
    if !is_control && payload_len > MAX_WS_FRAME_BYTES {
        return Err(WsProtocolError::TooLarge);
    }
    let header_len = 2 + length_field_bytes + 4;
    debug_assert!(header_len <= MAX_HEADER_BYTES);
    let total_len = header_len
        .checked_add(payload_len)
        .ok_or(WsProtocolError::TooLarge)?;
    if buf.len() < total_len {
        return Ok(None);
    }
    let mask_offset = 2 + length_field_bytes;
    let mask = [
        buf[mask_offset],
        buf[mask_offset + 1],
        buf[mask_offset + 2],
        buf[mask_offset + 3],
    ];
    let payload_offset = mask_offset + 4;
    let mut payload = buf[payload_offset..payload_offset + payload_len].to_vec();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    if opcode == WsOpcode::Text && std::str::from_utf8(&payload).is_err() {
        return Err(WsProtocolError::InvalidUtf8);
    }
    Ok(Some(ParsedFrame {
        opcode,
        payload,
        consumed: total_len,
    }))
}

/// Builds one unmasked server-to-client frame (RFC 6455 forbids the server
/// from masking its own frames).
///
/// # Panics
/// Never: the only fallible conversion is guarded by the `len <= 125` check
/// immediately before it.
#[must_use]
pub fn build_frame(opcode: WsOpcode, payload: &[u8]) -> Vec<u8> {
    let opcode_bits = match opcode {
        WsOpcode::Text => 0x1,
        WsOpcode::Binary => 0x2,
        WsOpcode::Close => 0x8,
        WsOpcode::Ping => 0x9,
        WsOpcode::Pong => 0xA,
    };
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x80 | opcode_bits);
    let len = payload.len();
    if len <= 125 {
        frame.push(u8::try_from(len).expect("<=125 fits in u8"));
    } else if let Ok(len16) = u16::try_from(len) {
        frame.push(126);
        frame.extend_from_slice(&len16.to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

/// Builds a close frame with an RFC 6455 close code and a short, bounded
/// printable-ASCII reason.
#[must_use]
pub fn close_frame(code: u16, reason: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    build_frame(WsOpcode::Close, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirrors the three-tier RFC 6455 length encoding `build_frame` uses, but
    // sets the mask bit and actually masks the payload, as a real client must.
    fn mask_client_frame(fin_opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let len = payload.len();
        let mut frame = vec![fin_opcode];
        if len <= 125 {
            frame.push(0x80 | u8::try_from(len).unwrap());
        } else if let Ok(len16) = u16::try_from(len) {
            frame.push(0x80 | 0x7e);
            frame.extend_from_slice(&len16.to_be_bytes());
        } else {
            frame.push(0x80 | 0x7f);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        frame
    }

    #[test]
    fn computes_the_rfc6455_example_accept_key() {
        // The exact handshake example from RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn validates_only_exactly_sixteen_bytes_of_base64() {
        assert!(valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ=="));
        for bad in [
            "short==",
            "",
            "dGhlIHNhbXBsZSBub25jZQ===",
            "not-base64-at-all-padding==",
            "dGhlIHNhbXBsZSBub25jZX",
        ] {
            assert!(!valid_websocket_key(bad), "{bad}");
        }
    }

    #[test]
    fn round_trips_one_masked_text_frame_and_reports_bytes_consumed() {
        let payload = br#"{"events":[]}"#;
        let frame = mask_client_frame(0x81, payload, [0x11, 0x22, 0x33, 0x44]);
        let trailing = [&frame[..], b"more"].concat();
        let parsed = parse_frame(&trailing).unwrap().unwrap();
        assert_eq!(parsed.opcode, WsOpcode::Text);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.consumed, frame.len());
    }

    #[test]
    fn waits_for_more_bytes_instead_of_erroring_on_a_split_frame() {
        let frame = mask_client_frame(0x81, b"hello", [1, 2, 3, 4]);
        for cut in 0..frame.len() {
            assert!(parse_frame(&frame[..cut]).unwrap().is_none(), "cut={cut}");
        }
        assert!(parse_frame(&frame).unwrap().is_some());
    }

    #[test]
    fn rejects_an_unmasked_client_frame() {
        let mut frame = vec![0x81, 0x05];
        frame.extend_from_slice(b"hello");
        assert_eq!(parse_frame(&frame), Err(WsProtocolError::Protocol));
    }

    #[test]
    fn rejects_reserved_bits_continuation_and_unknown_opcodes() {
        for fin_opcode in [0xC1u8, 0x80, 0x01, 0xF1] {
            let frame = mask_client_frame(fin_opcode, b"x", [1, 2, 3, 4]);
            assert_eq!(
                parse_frame(&frame),
                Err(WsProtocolError::Protocol),
                "{fin_opcode:#x}"
            );
        }
    }

    #[test]
    fn rejects_a_fragmented_text_frame() {
        // fin=0, opcode=text: the probe never fragments, so this is refused
        // rather than buffered waiting for a continuation that never comes.
        let frame = mask_client_frame(0x01, b"part", [1, 2, 3, 4]);
        assert_eq!(parse_frame(&frame), Err(WsProtocolError::Protocol));
    }

    #[test]
    fn rejects_an_oversized_data_frame_without_buffering_its_payload() {
        let mut frame = vec![0x81, 0xFE];
        frame.extend_from_slice(&u16::try_from(MAX_WS_FRAME_BYTES + 1).unwrap().to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        // No payload bytes appended at all: the length alone is refused.
        assert_eq!(parse_frame(&frame), Err(WsProtocolError::TooLarge));
    }

    #[test]
    fn rejects_an_oversized_control_frame() {
        let payload = vec![0u8; MAX_CONTROL_PAYLOAD_BYTES + 1];
        let frame = mask_client_frame(0x89, &payload, [1, 2, 3, 4]);
        assert_eq!(parse_frame(&frame), Err(WsProtocolError::Protocol));
    }

    #[test]
    fn rejects_invalid_utf8_in_a_text_frame() {
        let frame = mask_client_frame(0x81, &[0xff, 0xfe], [0, 0, 0, 0]);
        assert_eq!(parse_frame(&frame), Err(WsProtocolError::InvalidUtf8));
    }

    #[test]
    fn accepts_a_valid_ping_and_builds_an_unmasked_pong_reply() {
        let frame = mask_client_frame(0x89, b"keepalive", [9, 9, 9, 9]);
        let parsed = parse_frame(&frame).unwrap().unwrap();
        assert_eq!(parsed.opcode, WsOpcode::Ping);
        let pong = build_frame(WsOpcode::Pong, &parsed.payload);
        assert_eq!(pong[0], 0x8A);
        assert_eq!(pong[1] & 0x80, 0, "server frames are never masked");
        let echoed = parse_frame(&mask_client_frame(0x8A, &pong[2..], [1, 1, 1, 1]))
            .unwrap()
            .unwrap();
        assert_eq!(echoed.payload, b"keepalive");
    }

    #[test]
    fn builds_a_close_frame_carrying_the_code_and_reason() {
        let frame = close_frame(1008, "rate limited");
        assert_eq!(frame[0], 0x88);
        assert_eq!(&frame[2..4], &1008u16.to_be_bytes());
        assert_eq!(&frame[4..], b"rate limited");
    }

    #[test]
    fn builds_frames_spanning_all_three_length_encodings() {
        // 70_000 exceeds MAX_WS_FRAME_BYTES, so only its header shape (the
        // 64-bit extended length) is checked; it is never fed back through
        // the size-capped client-frame parser below.
        for (len, expected_length_bytes) in [(10, 1), (200, 3), (70_000, 9)] {
            let payload = vec![0x5Au8; len];
            let unmasked = build_frame(WsOpcode::Binary, &payload);
            assert_eq!(unmasked[1] & 0x80, 0, "server frames are never masked");
            let header_len = unmasked.len() - payload.len();
            assert_eq!(header_len, 1 + expected_length_bytes, "len={len}");
        }
        for len in [10, 200, MAX_WS_FRAME_BYTES] {
            let payload = vec![0x5Au8; len];
            let unmasked = build_frame(WsOpcode::Binary, &payload);
            let header_len = unmasked.len() - payload.len();
            // Mask the same header/payload shape as if a peer had sent it, to
            // drive it back through the strict client-frame parser.
            let mut as_client = unmasked[..header_len].to_vec();
            as_client[1] |= 0x80;
            as_client.extend_from_slice(&[0, 0, 0, 0]);
            as_client.extend_from_slice(&unmasked[header_len..]);
            let parsed = parse_frame(&as_client).unwrap().unwrap();
            assert_eq!(parsed.payload, payload, "len={len}");
        }
    }
}
