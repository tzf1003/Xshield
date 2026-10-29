//! Message-boundary audit for business WebSocket traffic proxied to a
//! protected site's own origin (docs/22 M2, the "无 WSS" gap).
//!
//! Unlike `sensor_ws` (which terminates a reserved, gateway-owned channel on
//! its own), a `business_websocket` operation never has the gateway
//! participate in framing: once its handshake is admitted, Pingora's own
//! HTTP/1 upgrade path relays the raw bytes verbatim in both directions (the
//! gateway is a dumb pipe at the byte level). This module only *observes*
//! those bytes as they pass through [`crate::main`]'s body filters, to
//! produce one audit record per logical message, independent of the single
//! handshake request (docs/11 §1: a business message carries its own
//! `message_id`, separate from the connection's admission).
//!
//! The scanner never blocks, rewrites, or drops a frame — relaying already
//! happened by the time it sees the bytes. A frame it cannot fully account
//! for (bigger than the configured observation cap, or framing it loses
//! track of) degrades that message's audit coverage instead of refusing
//! traffic: this module only ever runs under `OBSERVE`-style coverage
//! (docs/08 §8.5, "超大、不支持或截断包的覆盖状态必须显式").

/// One parsed frame's opcode class, generalized from RFC 6455 beyond the
/// narrow subset `sensor_ws` accepts: a business connection may fragment
/// messages (continuation frames) and send binary frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameKind {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    /// A reserved or unassigned opcode. Framing (the length field) is still
    /// trusted; only the kind is unknown.
    Other,
}

impl FrameKind {
    const fn from_bits(bits: u8) -> Self {
        match bits {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            _ => Self::Other,
        }
    }

    const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Continuation => "continuation",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Other => "other",
        }
    }
}

/// One audited business message: either a complete (possibly reassembled)
/// data message, or one control frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageAudit {
    /// `"text" | "binary" | "close" | "ping" | "pong" | "other"`.
    pub kind: &'static str,
    /// Total payload bytes across every frame of this message. Exact unless
    /// `degraded`, in which case it is the declared (not verified) length of
    /// whatever frame exceeded the observation cap.
    pub byte_len: u64,
    /// Number of wire frames this message was reassembled from (1 unless a
    /// data message was fragmented with continuation frames).
    pub frame_count: u32,
    /// Set when some frame of this message could not be fully accounted for:
    /// its payload exceeded the observation cap, it carried reserved bits
    /// this scanner does not interpret, or a continuation frame arrived with
    /// no message in progress. The byte stream itself was never altered;
    /// only this message's own audit coverage is incomplete.
    pub degraded: bool,
}

struct InProgress {
    kind: FrameKind,
    byte_len: u64,
    frame_count: u32,
    degraded: bool,
}

struct Skipping {
    remaining: u64,
    /// The frame's full declared payload length, kept alongside `remaining`
    /// so the completed message still reports how large the frame claimed
    /// to be once the skip finishes and `remaining` has reached zero.
    total: u64,
    fin: bool,
    kind: FrameKind,
}

/// A passive, per-direction, per-connection WebSocket message boundary
/// scanner. Feed it exactly the bytes relayed in one direction, in order;
/// [`Self::feed`] returns every message that completed during that call.
pub struct FrameScanner {
    /// Frames whose payload is at most this many bytes are fully accounted
    /// for; larger ones are still boundary-tracked (so later frames parse
    /// correctly) but contribute a degraded message record.
    observe_cap: usize,
    buf: Vec<u8>,
    skipping: Option<Skipping>,
    message: Option<InProgress>,
}

enum HeaderOutcome {
    NeedMore,
    /// A reserved length field could never be satisfied by any real frame
    /// (RFC 6455's 64-bit extended length does not fit `u64`... in practice
    /// always satisfiable; kept only so parsing never panics on garbage).
    Frame {
        header_len: usize,
        payload_len: u64,
        fin: bool,
        kind: FrameKind,
    },
}

fn parse_header(buf: &[u8]) -> HeaderOutcome {
    if buf.len() < 2 {
        return HeaderOutcome::NeedMore;
    }
    let first = buf[0];
    let second = buf[1];
    let fin = first & 0x80 != 0;
    let kind = FrameKind::from_bits(first & 0x0f);
    let masked = second & 0x80 != 0;
    let length_bits = second & 0x7f;
    let (payload_len, length_field_bytes): (u64, usize) = match length_bits {
        0..=125 => (u64::from(length_bits), 0),
        126 => {
            if buf.len() < 4 {
                return HeaderOutcome::NeedMore;
            }
            (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 2)
        }
        127 => {
            if buf.len() < 10 {
                return HeaderOutcome::NeedMore;
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[2..10]);
            (u64::from_be_bytes(raw), 8)
        }
        _ => unreachable!("7-bit field"),
    };
    let header_len = 2 + length_field_bytes + usize::from(masked) * 4;
    if buf.len() < header_len {
        return HeaderOutcome::NeedMore;
    }
    HeaderOutcome::Frame {
        header_len,
        payload_len,
        fin,
        kind,
    }
}

impl FrameScanner {
    /// Creates a scanner that fully accounts for frames up to
    /// `observe_cap` payload bytes; larger frames still advance correctly
    /// but degrade their message's audit record.
    #[must_use]
    pub fn new(observe_cap: usize) -> Self {
        Self {
            observe_cap,
            buf: Vec::new(),
            skipping: None,
            message: None,
        }
    }

    /// Feeds the next chunk of bytes relayed in this scanner's direction.
    /// Returns every message ([`MessageAudit`]) that completed as a result.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<MessageAudit> {
        let mut out = Vec::new();
        let mut rest = chunk;
        if self.skipping.is_some() {
            let (consumed, continue_scanning) = self.advance_skip(rest.len(), &mut out);
            rest = &rest[consumed..];
            if !continue_scanning {
                return out;
            }
        }
        self.buf.extend_from_slice(rest);
        loop {
            match parse_header(&self.buf) {
                HeaderOutcome::NeedMore => break,
                HeaderOutcome::Frame {
                    header_len,
                    payload_len,
                    fin,
                    kind,
                } => {
                    let payload_fits_cap = usize::try_from(payload_len)
                        .is_ok_and(|payload_len| payload_len <= self.observe_cap);
                    if payload_fits_cap {
                        // `payload_fits_cap` just proved this fits `usize`.
                        let total = header_len + usize::try_from(payload_len).unwrap_or(0);
                        if self.buf.len() < total {
                            break;
                        }
                        self.buf.drain(0..total);
                        self.finish_frame(kind, fin, payload_len, false, &mut out);
                    } else {
                        self.buf.drain(0..header_len);
                        self.skipping = Some(Skipping {
                            remaining: payload_len,
                            total: payload_len,
                            fin,
                            kind,
                        });
                        let (consumed, continue_scanning) =
                            self.advance_skip(self.buf.len(), &mut out);
                        self.buf.drain(0..consumed);
                        if !continue_scanning {
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    /// Advances the in-progress skip by up to `available` bytes (bytes the
    /// caller has but has not yet removed from wherever it is holding them).
    /// Returns how many of those bytes the skip consumed, and whether the
    /// caller should keep scanning for more frames (`false` while the skip
    /// is still pending after consuming all of `available`).
    ///
    /// # Panics
    /// Never: only called while `self.skipping` is `Some`.
    fn advance_skip(&mut self, available: usize, out: &mut Vec<MessageAudit>) -> (usize, bool) {
        let skip = self.skipping.as_mut().expect("caller checked Some");
        let take = skip.remaining.min(u64::try_from(available).unwrap_or(u64::MAX));
        skip.remaining -= take;
        // `take <= available`, which is itself a `usize`, so this always fits.
        let take = usize::try_from(take).unwrap_or(available);
        if skip.remaining > 0 {
            return (take, false);
        }
        let Skipping {
            fin, kind, total, ..
        } = self.skipping.take().expect("checked above");
        self.finish_frame(kind, fin, total, true, out);
        (take, true)
    }

    /// Folds one fully-accounted frame (`degraded_len` is the frame's
    /// payload length when it was only skip-tracked, else the frame already
    /// contributed its real length via the caller) into the in-progress
    /// message, emitting a completed [`MessageAudit`] on `out` when the
    /// message closes.
    fn finish_frame(
        &mut self,
        kind: FrameKind,
        fin: bool,
        frame_len: u64,
        was_skipped: bool,
        out: &mut Vec<MessageAudit>,
    ) {
        let degraded = was_skipped;
        if kind.is_control() {
            out.push(MessageAudit {
                kind: kind.as_str(),
                byte_len: frame_len,
                frame_count: 1,
                degraded,
            });
            return;
        }
        match kind {
            FrameKind::Continuation => {
                if let Some(message) = self.message.as_mut() {
                    message.byte_len += frame_len;
                    message.frame_count += 1;
                    message.degraded |= degraded;
                    if fin {
                        let message = self.message.take().expect("checked above");
                        out.push(MessageAudit {
                            kind: message.kind.as_str(),
                            byte_len: message.byte_len,
                            frame_count: message.frame_count,
                            degraded: message.degraded,
                        });
                    }
                } else {
                    // An orphan continuation: there is nothing to attach it
                    // to, so it is audited as its own degraded message
                    // rather than silently dropped or misattributed.
                    out.push(MessageAudit {
                        kind: FrameKind::Other.as_str(),
                        byte_len: frame_len,
                        frame_count: 1,
                        degraded: true,
                    });
                }
            }
            FrameKind::Text | FrameKind::Binary => {
                if fin {
                    out.push(MessageAudit {
                        kind: kind.as_str(),
                        byte_len: frame_len,
                        frame_count: 1,
                        degraded,
                    });
                } else {
                    self.message = Some(InProgress {
                        kind,
                        byte_len: frame_len,
                        frame_count: 1,
                        degraded,
                    });
                }
            }
            FrameKind::Other => {
                out.push(MessageAudit {
                    kind: kind.as_str(),
                    byte_len: frame_len,
                    frame_count: 1,
                    degraded: true,
                });
            }
            FrameKind::Close | FrameKind::Ping | FrameKind::Pong => unreachable!("is_control"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(fin_opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = vec![fin_opcode];
        let mask_bit = if mask.is_some() { 0x80 } else { 0x00 };
        if len <= 125 {
            out.push(mask_bit | u8::try_from(len).unwrap());
        } else if let Ok(len16) = u16::try_from(len) {
            out.push(mask_bit | 0x7e);
            out.extend_from_slice(&len16.to_be_bytes());
        } else {
            out.push(mask_bit | 0x7f);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if let Some(mask) = mask {
            out.extend_from_slice(&mask);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        } else {
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn audits_one_masked_text_frame_as_a_single_message() {
        let mut scanner = FrameScanner::new(64 * 1024);
        let wire = frame(0x81, Some([1, 2, 3, 4]), b"hello");
        let messages = scanner.feed(&wire);
        assert_eq!(
            messages,
            vec![MessageAudit {
                kind: "text",
                byte_len: 5,
                frame_count: 1,
                degraded: false,
            }]
        );
    }

    #[test]
    fn audits_an_unmasked_server_frame_the_same_way() {
        let mut scanner = FrameScanner::new(64 * 1024);
        let wire = frame(0x82, None, b"binarydata");
        let messages = scanner.feed(&wire);
        assert_eq!(messages[0].kind, "binary");
        assert_eq!(messages[0].byte_len, 10);
        assert!(!messages[0].degraded);
    }

    #[test]
    fn reassembles_a_fragmented_text_message_across_continuation_frames() {
        let mut scanner = FrameScanner::new(64 * 1024);
        let mut wire = frame(0x01, Some([9, 9, 9, 9]), b"hel");
        wire.extend(frame(0x00, Some([1, 1, 1, 1]), b"lo"));
        wire.extend(frame(0x80, Some([2, 2, 2, 2]), b"!"));
        let messages = scanner.feed(&wire);
        assert_eq!(
            messages,
            vec![MessageAudit {
                kind: "text",
                byte_len: 6,
                frame_count: 3,
                degraded: false,
            }]
        );
    }

    #[test]
    fn waits_for_more_bytes_across_an_arbitrarily_split_frame() {
        let wire = frame(0x81, Some([1, 2, 3, 4]), b"hello world");
        for cut in 1..wire.len() {
            let mut scanner = FrameScanner::new(64 * 1024);
            let mut all = Vec::new();
            all.extend(scanner.feed(&wire[..cut]));
            all.extend(scanner.feed(&wire[cut..]));
            assert_eq!(all.len(), 1, "cut={cut}");
            assert_eq!(all[0].byte_len, 11, "cut={cut}");
            assert!(!all[0].degraded, "cut={cut}");
        }
    }

    #[test]
    fn degrades_but_still_tracks_boundaries_past_an_oversized_frame() {
        let mut scanner = FrameScanner::new(8);
        let big = vec![0x5A; 200];
        let mut wire = frame(0x82, Some([1, 2, 3, 4]), &big);
        wire.extend(frame(0x81, Some([5, 6, 7, 8]), b"next"));
        let messages = scanner.feed(&wire);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].kind, "binary");
        assert_eq!(messages[0].byte_len, 200);
        assert!(messages[0].degraded);
        assert_eq!(messages[1].kind, "text");
        assert_eq!(messages[1].byte_len, 4);
        assert!(!messages[1].degraded);
    }

    #[test]
    fn splits_an_oversized_frames_skip_across_several_feed_calls() {
        let mut scanner = FrameScanner::new(4);
        let big = vec![0x11; 50];
        let mut wire = frame(0x82, None, &big);
        wire.extend(frame(0x89, None, b"bye"));
        let mut messages = Vec::new();
        for byte in wire {
            messages.extend(scanner.feed(&[byte]));
        }
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].byte_len, 50);
        assert!(messages[0].degraded);
        assert_eq!(messages[1].kind, "ping");
        assert!(!messages[1].degraded);
    }

    #[test]
    fn audits_each_control_frame_on_its_own_even_mid_fragmentation() {
        let mut scanner = FrameScanner::new(64 * 1024);
        let mut wire = frame(0x01, Some([1, 1, 1, 1]), b"part1");
        wire.extend(frame(0x89, Some([2, 2, 2, 2]), b"ping-mid-message"));
        wire.extend(frame(0x80, Some([3, 3, 3, 3]), b"part2"));
        let messages = scanner.feed(&wire);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].kind, "ping");
        assert_eq!(messages[1].kind, "text");
        assert_eq!(messages[1].byte_len, 10);
        assert_eq!(messages[1].frame_count, 2);
    }

    #[test]
    fn audits_an_orphan_continuation_as_its_own_degraded_message() {
        let mut scanner = FrameScanner::new(64 * 1024);
        let wire = frame(0x80, Some([1, 2, 3, 4]), b"stray");
        let messages = scanner.feed(&wire);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].kind, "other");
        assert!(messages[0].degraded);
    }

    #[test]
    fn tolerates_reserved_bits_and_unknown_opcodes_without_losing_sync() {
        let mut scanner = FrameScanner::new(64 * 1024);
        // RSV1 set (compression extension this scanner does not interpret),
        // immediately followed by a normal frame: boundaries must still land
        // correctly because the length field is unaffected by RSV bits.
        let mut wire = frame(0xC1, Some([1, 2, 3, 4]), b"compressed-ish");
        wire.extend(frame(0x81, Some([5, 6, 7, 8]), b"normal"));
        let messages = scanner.feed(&wire);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1].kind, "text");
        assert_eq!(messages[1].byte_len, 6);
        assert!(!messages[1].degraded);
    }
}
