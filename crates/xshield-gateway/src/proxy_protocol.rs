//! PROXY protocol v1 (text) and v2 (binary) headers from trusted balancers.
//!
//! Trust boundary: a TCP balancer in front of the edge can say which client it
//! relays for by prefixing the stream with a PROXY header (haproxy
//! `proxy-protocol.txt`). Those bytes are attacker-controlled unless they come
//! from a balancer the operator listed, so whether a connection may carry a
//! header at all is decided by [`TrustedProxies`] against the socket's real
//! peer address before any byte is read, never from anything in the stream.
//!
//! [`parse_header`] only interprets bytes: it allocates nothing, cannot panic
//! (every index is checked) and trusts no length before bounding it by the
//! version's limit. TLVs in a v2 header are skipped uninterpreted, so no
//! authority, SNI or other balancer claim is believed. [`read_header`] is the
//! only I/O here and reads at most [`MAX_HEADER_BYTES`] bytes.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Longest v1 header including its CRLF (the spec's 107 characters; its
/// 108-byte buffer adds the C string terminator).
pub const V1_MAX_HEADER_BYTES: usize = 107;
/// Longest v2 header accepted: the 16-byte fixed part plus address block and
/// TLVs. 536 bytes is the spec's minimum receive size (the IPv4 minimum MSS).
pub const V2_MAX_HEADER_BYTES: usize = 536;
/// Largest number of bytes [`read_header`] ever buffers.
pub const MAX_HEADER_BYTES: usize = V2_MAX_HEADER_BYTES;

const V1_PREFIX: &[u8] = b"PROXY ";
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const V2_FIXED_BYTES: usize = 16;
const V2_COMMAND_LOCAL: u8 = 0x0;
const V2_COMMAND_PROXY: u8 = 0x1;
/// Most CIDR blocks one deployment may list; the check runs per connection.
const MAX_TRUSTED_BLOCKS: usize = 64;

/// What a complete header says about the connection's client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvertisedClient {
    /// A PROXY command for TCP over IPv4 or IPv6: this is the client.
    Address(SocketAddr),
    /// A LOCAL command (the balancer's own health check) or an UNKNOWN/UNSPEC
    /// family: the TCP peer stays the client.
    Connection,
}

/// Result of inspecting the bytes received so far.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderParse {
    /// The bytes are a strict prefix of a header that may still be valid.
    Incomplete,
    /// A complete header occupies the first `length` bytes; anything after
    /// them belongs to the relayed stream.
    Complete {
        /// Header length in bytes, including the v1 CRLF or v2 TLVs.
        length: usize,
        /// The client the header names.
        client: AdvertisedClient,
    },
}

/// Why a trusted peer's leading bytes are not an acceptable header. Every
/// variant closes the connection; none falls back to the TCP peer address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    /// The stream does not start with a v1 or v2 signature.
    Missing,
    /// The header exceeds its version's size limit.
    Oversized,
    /// The signature matched but the rest is not a valid header.
    Malformed,
    /// A well-formed v2 header names a datagram or UNIX socket client, which
    /// an HTTP edge cannot attribute to an IP address.
    UnsupportedTransport,
    /// The stream ended or failed before a complete header arrived.
    Truncated,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "PROXY header missing",
            Self::Oversized => "PROXY header too large",
            Self::Malformed => "PROXY header malformed",
            Self::UnsupportedTransport => "PROXY header names an unsupported transport",
            Self::Truncated => "connection ended inside the PROXY header",
        })
    }
}

impl std::error::Error for HeaderError {}

/// Classifies the first bytes of a trusted connection.
///
/// Returns [`HeaderParse::Incomplete`] only while the bytes are a strict
/// prefix of a header that can still fit its version's limit, so a caller
/// that reads until `Complete` or an error buffers at most
/// [`MAX_HEADER_BYTES`]. Bytes after a complete header are not inspected.
///
/// # Errors
/// [`HeaderError`] as soon as the bytes cannot start a valid header.
pub fn parse_header(bytes: &[u8]) -> Result<HeaderParse, HeaderError> {
    match bytes.first() {
        None => Ok(HeaderParse::Incomplete),
        Some(b'\r') => match_signature(bytes, V2_SIGNATURE).and_then(|complete| {
            if complete {
                parse_v2(bytes)
            } else {
                Ok(HeaderParse::Incomplete)
            }
        }),
        Some(b'P') => match_signature(bytes, V1_PREFIX).and_then(|complete| {
            if complete {
                parse_v1(bytes)
            } else {
                Ok(HeaderParse::Incomplete)
            }
        }),
        Some(_) => Err(HeaderError::Missing),
    }
}

/// `Ok(true)` when `bytes` starts with the whole signature, `Ok(false)` when
/// they are a shorter prefix of it.
fn match_signature(bytes: &[u8], signature: &[u8]) -> Result<bool, HeaderError> {
    let compared = bytes.len().min(signature.len());
    if bytes.get(..compared) == signature.get(..compared) {
        Ok(compared == signature.len())
    } else {
        Err(HeaderError::Missing)
    }
}

fn parse_v1(bytes: &[u8]) -> Result<HeaderParse, HeaderError> {
    let window = bytes.get(..V1_MAX_HEADER_BYTES).unwrap_or(bytes);
    let Some(newline) = window.iter().position(|byte| *byte == b'\n') else {
        if window.len() >= V1_MAX_HEADER_BYTES {
            return Err(HeaderError::Oversized);
        }
        // Refuse garbage now instead of waiting for a newline that would
        // only confirm it; a trailing CR may still be followed by LF.
        let (last, body) = window.split_last().ok_or(HeaderError::Malformed)?;
        if !body.iter().all(|byte| header_text_byte(*byte))
            || !(header_text_byte(*last) || *last == b'\r')
        {
            return Err(HeaderError::Malformed);
        }
        return Ok(HeaderParse::Incomplete);
    };
    let line = window
        .get(..newline)
        .and_then(|line| line.strip_suffix(b"\r"))
        .ok_or(HeaderError::Malformed)?;
    if !line.iter().all(|byte| header_text_byte(*byte)) {
        return Err(HeaderError::Malformed);
    }
    let fields = std::str::from_utf8(line)
        .ok()
        .and_then(|line| line.strip_prefix("PROXY "))
        .ok_or(HeaderError::Malformed)?;
    Ok(HeaderParse::Complete {
        length: newline + 1,
        client: parse_v1_fields(fields)?,
    })
}

fn parse_v1_fields(fields: &str) -> Result<AdvertisedClient, HeaderError> {
    let mut fields = fields.split(' ');
    let family = fields.next();
    if family == Some("UNKNOWN") {
        // The spec tells receivers to ignore everything up to the CRLF.
        return Ok(AdvertisedClient::Connection);
    }
    let parse_address = |field: Option<&str>| -> Result<IpAddr, HeaderError> {
        let field = field.ok_or(HeaderError::Malformed)?;
        match family {
            Some("TCP4") => Ipv4Addr::from_str(field).map(IpAddr::V4),
            Some("TCP6") => Ipv6Addr::from_str(field).map(IpAddr::V6),
            _ => return Err(HeaderError::Malformed),
        }
        .map_err(|_| HeaderError::Malformed)
    };
    let source = parse_address(fields.next())?;
    parse_address(fields.next())?;
    let source_port = parse_v1_port(fields.next())?;
    parse_v1_port(fields.next())?;
    if fields.next().is_some() {
        return Err(HeaderError::Malformed);
    }
    Ok(AdvertisedClient::Address(SocketAddr::new(
        source,
        source_port,
    )))
}

/// Decimal 0..=65535 without sign, spaces or leading zeros.
fn parse_v1_port(field: Option<&str>) -> Result<u16, HeaderError> {
    let field = field.ok_or(HeaderError::Malformed)?;
    if field.is_empty()
        || field.len() > 5
        || !field.bytes().all(|byte| byte.is_ascii_digit())
        || (field.len() > 1 && field.starts_with('0'))
    {
        return Err(HeaderError::Malformed);
    }
    field.parse().map_err(|_| HeaderError::Malformed)
}

fn parse_v2(bytes: &[u8]) -> Result<HeaderParse, HeaderError> {
    let Some(&version_command) = bytes.get(V2_SIGNATURE.len()) else {
        return Ok(HeaderParse::Incomplete);
    };
    let command = version_command & 0x0f;
    if version_command >> 4 != 2 || (command != V2_COMMAND_LOCAL && command != V2_COMMAND_PROXY) {
        return Err(HeaderError::Malformed);
    }
    // A LOCAL header's family is ignored; a PROXY header's is checked as soon
    // as it arrives so a refused transport never waits for its block.
    let family = match bytes.get(V2_SIGNATURE.len() + 1) {
        Some(&family) if command == V2_COMMAND_PROXY => Some(V2Family::parse(family)?),
        _ => None,
    };
    let Some((fixed, _)) = bytes.split_first_chunk::<V2_FIXED_BYTES>() else {
        return Ok(HeaderParse::Incomplete);
    };
    let [.., high, low] = *fixed;
    let length = V2_FIXED_BYTES + usize::from(u16::from_be_bytes([high, low]));
    if length > V2_MAX_HEADER_BYTES {
        return Err(HeaderError::Oversized);
    }
    let Some(block) = bytes.get(V2_FIXED_BYTES..length) else {
        return Ok(HeaderParse::Incomplete);
    };
    let client = match family {
        None => AdvertisedClient::Connection,
        Some(family) => family.client(block)?,
    };
    Ok(HeaderParse::Complete { length, client })
}

/// The v2 address families an HTTP edge can honour.
#[derive(Clone, Copy)]
enum V2Family {
    Unspecified,
    Tcp4,
    Tcp6,
}

impl V2Family {
    fn parse(family: u8) -> Result<Self, HeaderError> {
        match family {
            0x00 => Ok(Self::Unspecified),
            0x11 => Ok(Self::Tcp4),
            0x21 => Ok(Self::Tcp6),
            // UDP over IPv4/IPv6, UNIX stream/datagram: valid wire values that
            // an HTTP edge cannot turn into a client IP address.
            0x12 | 0x22 | 0x31 | 0x32 => Err(HeaderError::UnsupportedTransport),
            _ => Err(HeaderError::Malformed),
        }
    }

    /// Reads the source from an address block; TLVs after it are skipped.
    fn client(self, block: &[u8]) -> Result<AdvertisedClient, HeaderError> {
        // Layout: source address, destination address, source port,
        // destination port; the block must hold all four.
        let (address, ports) = match self {
            // UNSPEC: the spec lets receivers keep the real endpoints.
            Self::Unspecified => return Ok(AdvertisedClient::Connection),
            Self::Tcp4 => {
                let (source, rest) = block
                    .split_first_chunk::<4>()
                    .ok_or(HeaderError::Malformed)?;
                let ports = rest.get(4..).ok_or(HeaderError::Malformed)?;
                (IpAddr::V4(Ipv4Addr::from(*source)), ports)
            }
            Self::Tcp6 => {
                let (source, rest) = block
                    .split_first_chunk::<16>()
                    .ok_or(HeaderError::Malformed)?;
                let ports = rest.get(16..).ok_or(HeaderError::Malformed)?;
                (IpAddr::V6(Ipv6Addr::from(*source)), ports)
            }
        };
        let (&[high, low, _, _], _) = ports
            .split_first_chunk::<4>()
            .ok_or(HeaderError::Malformed)?;
        Ok(AdvertisedClient::Address(SocketAddr::new(
            address,
            u16::from_be_bytes([high, low]),
        )))
    }
}

/// Reads one header from a stream whose peer is a trusted balancer.
///
/// Returns the advertised client and the bytes read past the header, which
/// the caller must put back in front of the stream. The caller bounds the
/// time spent here; the size is bounded by [`MAX_HEADER_BYTES`].
///
/// # Errors
/// [`HeaderError`] for a missing, oversized or malformed header, and
/// [`HeaderError::Truncated`] when the stream ends or fails first.
pub async fn read_header<R>(stream: &mut R) -> Result<(AdvertisedClient, Vec<u8>), HeaderError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; MAX_HEADER_BYTES];
    let mut filled = 0;
    loop {
        let received = buffer.get(..filled).ok_or(HeaderError::Oversized)?;
        if let HeaderParse::Complete { length, client } = parse_header(received)? {
            let surplus = received.get(length..).unwrap_or_default().to_vec();
            return Ok((client, surplus));
        }
        // `Incomplete` is only returned below the version's limit, so there
        // is always spare room; the check keeps that a local fact.
        let spare = buffer
            .get_mut(filled..)
            .filter(|spare| !spare.is_empty())
            .ok_or(HeaderError::Oversized)?;
        let read = stream
            .read(spare)
            .await
            .map_err(|_| HeaderError::Truncated)?;
        if read == 0 {
            return Err(HeaderError::Truncated);
        }
        filled += read;
    }
}

/// Printable ASCII and space: the only bytes a v1 line may contain.
fn header_text_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() || byte == b' '
}

/// The balancers allowed to send a PROXY header, as CIDR blocks.
///
/// Matching uses the canonical form of the peer address, so an IPv4 client
/// seen through an IPv4-mapped IPv6 socket matches its IPv4 block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedProxies {
    blocks: Vec<CidrBlock>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CidrBlock {
    network: IpAddr,
    prefix: u8,
}

/// Why a trusted-balancer list was refused; startup stops on any of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustedProxiesError {
    /// An entry between commas is empty.
    EmptyEntry {
        /// One-based position in the list.
        position: usize,
    },
    /// An entry is neither an IP address nor `address/prefix`.
    InvalidEntry {
        /// One-based position in the list.
        position: usize,
    },
    /// An entry has address bits outside its prefix, which usually means a
    /// mistyped prefix length.
    HostBitsSet {
        /// One-based position in the list.
        position: usize,
    },
    /// An entry with prefix length zero would trust every peer, so any client
    /// could choose its own address.
    MatchesEverything {
        /// One-based position in the list.
        position: usize,
    },
    /// An IPv4-mapped IPv6 block never matches: peers are compared in their
    /// canonical IPv4 form, so the IPv4 block must be listed instead.
    MappedIpv4 {
        /// One-based position in the list.
        position: usize,
    },
    /// The list exceeds the supported number of blocks.
    TooManyEntries,
}

impl fmt::Display for TrustedProxiesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEntry { position } => write!(formatter, "entry {position} is empty"),
            Self::InvalidEntry { position } => write!(
                formatter,
                "entry {position} is not an IP address or address/prefix block"
            ),
            Self::HostBitsSet { position } => write!(
                formatter,
                "entry {position} has address bits outside its prefix"
            ),
            Self::MatchesEverything { position } => write!(
                formatter,
                "entry {position} has prefix length 0 and would trust every peer"
            ),
            Self::MappedIpv4 { position } => write!(
                formatter,
                "entry {position} is an IPv4-mapped IPv6 block; list the IPv4 block"
            ),
            Self::TooManyEntries => write!(
                formatter,
                "more than {MAX_TRUSTED_BLOCKS} trusted balancer blocks"
            ),
        }
    }
}

impl std::error::Error for TrustedProxiesError {}

impl TrustedProxies {
    /// Parses a comma-separated list of IP addresses and CIDR blocks.
    ///
    /// Returns `Ok(None)` for an empty or all-whitespace value, which leaves
    /// the PROXY protocol off. A bare address is a single-host block.
    ///
    /// # Errors
    /// [`TrustedProxiesError`] for any entry that is empty, unparsable, has
    /// host bits set, trusts everything, or is IPv4-mapped, and for lists
    /// longer than the supported maximum.
    pub fn parse(value: &str) -> Result<Option<Self>, TrustedProxiesError> {
        if value.trim().is_empty() {
            return Ok(None);
        }
        let mut blocks = Vec::new();
        for (index, entry) in value.split(',').enumerate() {
            let position = index + 1;
            if position > MAX_TRUSTED_BLOCKS {
                return Err(TrustedProxiesError::TooManyEntries);
            }
            blocks.push(CidrBlock::parse(entry.trim(), position)?);
        }
        Ok(Some(Self { blocks }))
    }

    /// Whether `peer` (the socket's real peer address) may send a header.
    #[must_use]
    pub fn contains(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.blocks.iter().any(|block| block.contains(peer))
    }
}

impl CidrBlock {
    fn parse(entry: &str, position: usize) -> Result<Self, TrustedProxiesError> {
        if entry.is_empty() {
            return Err(TrustedProxiesError::EmptyEntry { position });
        }
        let invalid = TrustedProxiesError::InvalidEntry { position };
        let (address, prefix) = match entry.split_once('/') {
            Some((address, prefix)) => {
                if prefix.is_empty()
                    || prefix.len() > 3
                    || !prefix.bytes().all(|byte| byte.is_ascii_digit())
                    || (prefix.len() > 1 && prefix.starts_with('0'))
                {
                    return Err(invalid);
                }
                (
                    address,
                    Some(prefix.parse::<u8>().map_err(|_| invalid.clone())?),
                )
            }
            None => (entry, None),
        };
        let network = IpAddr::from_str(address).map_err(|_| invalid.clone())?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(width);
        if prefix > width {
            return Err(invalid);
        }
        if prefix == 0 {
            return Err(TrustedProxiesError::MatchesEverything { position });
        }
        if let IpAddr::V6(v6) = network
            && v6.to_ipv4_mapped().is_some()
        {
            return Err(TrustedProxiesError::MappedIpv4 { position });
        }
        let block = Self { network, prefix };
        if block.masked(network) != network {
            return Err(TrustedProxiesError::HostBitsSet { position });
        }
        Ok(block)
    }

    fn masked(self, address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V4(v4) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.network.is_ipv4() && self.masked(address) == self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2(command: u8, family: u8, block: &[u8]) -> Vec<u8> {
        let mut header = V2_SIGNATURE.to_vec();
        header.push(0x20 | command);
        header.push(family);
        header.extend_from_slice(&u16::try_from(block.len()).unwrap().to_be_bytes());
        header.extend_from_slice(block);
        header
    }

    fn tcp4_block(source: [u8; 4], port: u16) -> Vec<u8> {
        let mut block = source.to_vec();
        block.extend_from_slice(&[10, 0, 0, 1]);
        block.extend_from_slice(&port.to_be_bytes());
        block.extend_from_slice(&443_u16.to_be_bytes());
        block
    }

    fn tcp6_block(source: Ipv6Addr, port: u16) -> Vec<u8> {
        let mut block = source.octets().to_vec();
        block.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        block.extend_from_slice(&port.to_be_bytes());
        block.extend_from_slice(&443_u16.to_be_bytes());
        block
    }

    fn complete(bytes: &[u8]) -> (usize, AdvertisedClient) {
        match parse_header(bytes) {
            Ok(HeaderParse::Complete { length, client }) => (length, client),
            other => panic!("expected a complete header, got {other:?}"),
        }
    }

    #[test]
    fn v1_tcp4_tcp6_and_unknown_headers_parse() {
        let line = b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443\r\nGET / HTTP/1.1\r\n";
        assert_eq!(
            complete(line),
            (
                44,
                AdvertisedClient::Address("198.51.100.7:51234".parse().unwrap())
            )
        );
        let line = b"PROXY TCP6 2001:db8::7 2001:db8::1 65535 443\r\n";
        assert_eq!(
            complete(line).1,
            AdvertisedClient::Address("[2001:db8::7]:65535".parse().unwrap())
        );
        for line in [
            &b"PROXY UNKNOWN\r\n"[..],
            b"PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n",
        ] {
            assert_eq!(complete(line), (line.len(), AdvertisedClient::Connection));
        }
        // Port zero is a valid value.
        assert_eq!(
            complete(b"PROXY TCP4 192.0.2.1 192.0.2.2 0 0\r\n").1,
            AdvertisedClient::Address("192.0.2.1:0".parse().unwrap())
        );
    }

    #[test]
    fn v1_longest_lines_fit_and_one_byte_more_does_not() {
        let longest = b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        assert_eq!(longest.len(), 104);
        assert_eq!(complete(longest).0, 104);
        let mut unknown = b"PROXY UNKNOWN ".to_vec();
        unknown.resize(V1_MAX_HEADER_BYTES - 2, b'x');
        unknown.extend_from_slice(b"\r\n");
        assert_eq!(complete(&unknown).0, V1_MAX_HEADER_BYTES);
        let mut oversized = b"PROXY UNKNOWN ".to_vec();
        oversized.resize(V1_MAX_HEADER_BYTES - 1, b'x');
        oversized.extend_from_slice(b"\r\n");
        assert_eq!(parse_header(&oversized), Err(HeaderError::Oversized));
        // Without any newline the limit is reached as soon as it is filled.
        assert_eq!(
            parse_header(&[b"PROXY ".as_slice(), &[b'x'; 200]].concat()),
            Err(HeaderError::Oversized)
        );
    }

    #[test]
    fn v1_rejects_every_malformed_shape() {
        for line in [
            &b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443\n"[..],
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443\r\r\n",
            b"PROXY TCP4  198.51.100.7 10.0.0.1 51234 443\r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443 \r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234\r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443 7\r\n",
            b"PROXY TCP4 2001:db8::7 10.0.0.1 51234 443\r\n",
            b"PROXY TCP6 198.51.100.7 2001:db8::1 51234 443\r\n",
            b"PROXY TCP4 198.51.100.07 10.0.0.1 51234 443\r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 65536 443\r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 051234 443\r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 +5123 443\r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 -1 443\r\n",
            b"PROXY TCP5 198.51.100.7 10.0.0.1 51234 443\r\n",
            b"PROXY tcp4 198.51.100.7 10.0.0.1 51234 443\r\n",
            b"PROXY UNKNOWNX\r\n",
            b"PROXY \r\n",
            b"PROXY TCP4 198.51.100.7\t10.0.0.1 51234 443\r\n",
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 4\x0043\r\n",
            b"PROXY UNKNOWN \xff\r\n",
        ] {
            assert_eq!(
                parse_header(line),
                Err(HeaderError::Malformed),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        // Garbage is refused before any newline arrives.
        assert_eq!(
            parse_header(b"PROXY TCP4 \x01"),
            Err(HeaderError::Malformed)
        );
        assert_eq!(
            parse_header(b"PROXY TCP4 1\rx"),
            Err(HeaderError::Malformed)
        );
        assert_eq!(parse_header(b"PROXY TCP4 1\r"), Ok(HeaderParse::Incomplete));
    }

    #[test]
    fn v2_ipv4_ipv6_local_and_unspec_headers_parse() {
        let header = v2(1, 0x11, &tcp4_block([203, 0, 113, 9], 40_000));
        assert_eq!(
            complete(&header),
            (
                28,
                AdvertisedClient::Address("203.0.113.9:40000".parse().unwrap())
            )
        );
        let source: Ipv6Addr = "2001:db8:1::9".parse().unwrap();
        let header = v2(1, 0x21, &tcp6_block(source, 1));
        assert_eq!(
            complete(&header),
            (
                52,
                AdvertisedClient::Address(SocketAddr::new(IpAddr::V6(source), 1))
            )
        );
        // LOCAL ignores family and block; UNSPEC keeps the connection peer.
        for header in [
            v2(0, 0x00, &[]),
            v2(0, 0x11, &tcp4_block([1, 2, 3, 4], 5)),
            v2(0, 0x77, &[1, 2, 3]),
            v2(1, 0x00, &[]),
            v2(1, 0x00, &[9; 40]),
        ] {
            assert_eq!(
                complete(&header),
                (header.len(), AdvertisedClient::Connection)
            );
        }
    }

    #[test]
    fn v2_skips_tlvs_without_trusting_them_and_honours_the_size_limit() {
        // An authority TLV (type 0x02) claiming another host changes nothing.
        let mut block = tcp4_block([203, 0, 113, 9], 40_000);
        block.extend_from_slice(&[0x02, 0x00, 0x0c]);
        block.extend_from_slice(b"evil.example");
        let header = v2(1, 0x11, &block);
        let mut stream = header.clone();
        stream.extend_from_slice(b"\x16\x03\x01");
        assert_eq!(
            complete(&stream),
            (
                header.len(),
                AdvertisedClient::Address("203.0.113.9:40000".parse().unwrap())
            )
        );
        let largest = v2(1, 0x11, &[0; V2_MAX_HEADER_BYTES - V2_FIXED_BYTES]);
        assert_eq!(complete(&largest).0, V2_MAX_HEADER_BYTES);
        let oversized = v2(1, 0x11, &[0; V2_MAX_HEADER_BYTES - V2_FIXED_BYTES + 1]);
        // Refused from the length field alone, before the block is read.
        assert_eq!(
            parse_header(&oversized[..V2_FIXED_BYTES]),
            Err(HeaderError::Oversized)
        );
        let mut length_max = v2(1, 0x11, &[]);
        length_max[14] = 0xff;
        length_max[15] = 0xff;
        assert_eq!(parse_header(&length_max), Err(HeaderError::Oversized));
    }

    #[test]
    fn v2_rejects_bad_versions_commands_families_and_short_blocks() {
        let mut version_one = v2(1, 0x11, &tcp4_block([1, 2, 3, 4], 5));
        version_one[12] = 0x11;
        assert_eq!(parse_header(&version_one), Err(HeaderError::Malformed));
        let mut command_two = v2(1, 0x11, &tcp4_block([1, 2, 3, 4], 5));
        command_two[12] = 0x22;
        assert_eq!(parse_header(&command_two), Err(HeaderError::Malformed));
        // The command is checked as soon as its byte arrives.
        assert_eq!(
            parse_header(&command_two[..13]),
            Err(HeaderError::Malformed)
        );
        assert_eq!(
            parse_header(&v2(1, 0x11, &[1; 11])),
            Err(HeaderError::Malformed)
        );
        assert_eq!(
            parse_header(&v2(1, 0x21, &[1; 35])),
            Err(HeaderError::Malformed)
        );
        for family in [0x12, 0x22, 0x31, 0x32] {
            assert_eq!(
                parse_header(&v2(1, family, &[0; 216])),
                Err(HeaderError::UnsupportedTransport)
            );
        }
        for family in [0x01, 0x10, 0x13, 0x41, 0xff] {
            assert_eq!(
                parse_header(&v2(1, family, &[0; 36])),
                Err(HeaderError::Malformed)
            );
        }
    }

    #[test]
    fn every_strict_prefix_of_a_valid_header_is_incomplete() {
        let headers = [
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443\r\n".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            v2(1, 0x11, &tcp4_block([203, 0, 113, 9], 40_000)),
            v2(1, 0x21, &tcp6_block(Ipv6Addr::LOCALHOST, 7)),
            v2(0, 0x00, &[]),
        ];
        for header in headers {
            for end in 0..header.len() {
                assert_eq!(
                    parse_header(&header[..end]),
                    Ok(HeaderParse::Incomplete),
                    "prefix of {end} bytes"
                );
            }
            assert!(matches!(
                parse_header(&header),
                Ok(HeaderParse::Complete { .. })
            ));
        }
    }

    #[test]
    fn ordinary_protocol_bytes_are_not_headers() {
        for bytes in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"POST / HTTP/1.1\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"\x16\x03\x01\x02\x00\x01",
            b"\r\n\r\nGET",
            b"PROXX TCP4",
            b"proxy TCP4",
            b"\0",
        ] {
            assert_eq!(parse_header(bytes), Err(HeaderError::Missing), "{bytes:?}");
        }
    }

    /// Deterministic xorshift so the fuzz corpus is reproducible in CI.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
        }
    }

    /// Fuzz-style: random and mutated inputs never panic, never claim more
    /// bytes than given, never accept beyond a version's limit, and only
    /// report `Incomplete` while a version's limit has not been reached.
    #[test]
    fn random_and_mutated_inputs_respect_the_parser_contract() {
        let seeds = [
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443\r\n".to_vec(),
            b"PROXY TCP6 2001:db8::7 2001:db8::1 1 2\r\n".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            v2(1, 0x11, &tcp4_block([203, 0, 113, 9], 40_000)),
            v2(1, 0x21, &tcp6_block(Ipv6Addr::LOCALHOST, 7)),
            v2(0, 0x00, &[]),
        ];
        let mut random = XorShift(0x5eed_1234_abcd_ef01);
        for round in 0..60_000 {
            let mut input = if round % 3 == 0 {
                let length = random.below(700);
                (0..length)
                    .map(|_| u8::try_from(random.next() & 0xff).unwrap())
                    .collect::<Vec<_>>()
            } else {
                seeds[random.below(seeds.len())].clone()
            };
            for _ in 0..random.below(4) {
                if input.is_empty() {
                    break;
                }
                let position = random.below(input.len());
                match random.below(4) {
                    0 => input[position] = u8::try_from(random.next() & 0xff).unwrap(),
                    1 => input.truncate(position),
                    2 => input.insert(position, u8::try_from(random.next() & 0xff).unwrap()),
                    _ => input.extend((0..random.below(600)).map(|_| b'A')),
                }
            }
            match parse_header(&input) {
                Ok(HeaderParse::Complete { length, .. }) => {
                    assert!(length <= input.len());
                    let limit = if input.first() == Some(&b'P') {
                        V1_MAX_HEADER_BYTES
                    } else {
                        V2_MAX_HEADER_BYTES
                    };
                    assert!(length <= limit, "accepted {length} bytes");
                }
                Ok(HeaderParse::Incomplete) => {
                    assert!(input.len() < MAX_HEADER_BYTES, "{} bytes", input.len());
                    if input.first() == Some(&b'P') {
                        assert!(input.len() < V1_MAX_HEADER_BYTES);
                    }
                }
                Err(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn reading_returns_the_bytes_after_the_header() {
        let mut stream: &[u8] =
            b"PROXY TCP4 198.51.100.7 10.0.0.1 51234 443\r\nGET / HTTP/1.1\r\n\r\n";
        let (client, surplus) = read_header(&mut stream).await.unwrap();
        assert_eq!(
            client,
            AdvertisedClient::Address("198.51.100.7:51234".parse().unwrap())
        );
        assert_eq!(surplus, b"GET / HTTP/1.1\r\n\r\n");
        let header = v2(1, 0x11, &tcp4_block([203, 0, 113, 9], 40_000));
        let mut wire = header.clone();
        wire.extend_from_slice(b"\x16\x03\x01");
        let mut stream = wire.as_slice();
        let (_, surplus) = read_header(&mut stream).await.unwrap();
        assert_eq!(surplus, b"\x16\x03\x01");
    }

    #[tokio::test]
    async fn reading_assembles_headers_split_across_reads() {
        let header = v2(1, 0x21, &tcp6_block("2001:db8::5".parse().unwrap(), 9));
        let mut builder = tokio_test_reader(&header, 3);
        let (client, surplus) = read_header(&mut builder).await.unwrap();
        assert_eq!(
            client,
            AdvertisedClient::Address("[2001:db8::5]:9".parse().unwrap())
        );
        assert!(surplus.is_empty());
    }

    #[tokio::test]
    async fn reading_fails_closed_on_early_end_and_on_garbage() {
        let mut truncated: &[u8] = b"PROXY TCP4 198.51.100.7";
        assert_eq!(
            read_header(&mut truncated).await,
            Err(HeaderError::Truncated)
        );
        let mut plain: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(read_header(&mut plain).await, Err(HeaderError::Missing));
        let mut endless = tokio_test_reader(&[b'P'; 4096], 512);
        assert_eq!(read_header(&mut endless).await, Err(HeaderError::Missing));
        let mut long_line = tokio_test_reader(&[b"PROXY ".as_slice(), &[b'1'; 4096]].concat(), 64);
        assert_eq!(
            read_header(&mut long_line).await,
            Err(HeaderError::Oversized)
        );
    }

    /// A reader that hands out `chunk` bytes per read, to exercise reassembly.
    fn tokio_test_reader(bytes: &[u8], chunk: usize) -> ChunkedReader {
        ChunkedReader {
            bytes: bytes.to_vec(),
            position: 0,
            chunk,
        }
    }

    struct ChunkedReader {
        bytes: Vec<u8>,
        position: usize,
        chunk: usize,
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let end = (self.position + self.chunk)
                .min(self.bytes.len())
                .min(self.position + buf.remaining());
            let start = self.position;
            buf.put_slice(&self.bytes[start..end]);
            self.position = end;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn trusted_blocks_parse_strictly() {
        assert_eq!(TrustedProxies::parse(""), Ok(None));
        assert_eq!(TrustedProxies::parse("  "), Ok(None));
        let trusted = TrustedProxies::parse("10.0.0.0/8, 192.168.1.10 ,fd00:ab::/32,::1")
            .unwrap()
            .unwrap();
        for peer in [
            "10.1.2.3",
            "192.168.1.10",
            "fd00:ab:1::9",
            "::1",
            "::ffff:10.9.9.9",
        ] {
            assert!(trusted.contains(peer.parse().unwrap()), "{peer}");
        }
        for peer in ["11.0.0.1", "192.168.1.11", "fd00:ac::1", "::2", "127.0.0.1"] {
            assert!(!trusted.contains(peer.parse().unwrap()), "{peer}");
        }
        for (value, expected) in [
            (
                "10.0.0.0/8,",
                TrustedProxiesError::EmptyEntry { position: 2 },
            ),
            (
                ",10.0.0.0/8",
                TrustedProxiesError::EmptyEntry { position: 1 },
            ),
            (
                "10.0.0.0/33",
                TrustedProxiesError::InvalidEntry { position: 1 },
            ),
            (
                "10.0.0.0/08",
                TrustedProxiesError::InvalidEntry { position: 1 },
            ),
            (
                "10.0.0.0/",
                TrustedProxiesError::InvalidEntry { position: 1 },
            ),
            (
                "10.0.0.0/+8",
                TrustedProxiesError::InvalidEntry { position: 1 },
            ),
            (
                "example.com",
                TrustedProxiesError::InvalidEntry { position: 1 },
            ),
            (
                "fd00::/129",
                TrustedProxiesError::InvalidEntry { position: 1 },
            ),
            (
                "10.0.0.1/8",
                TrustedProxiesError::HostBitsSet { position: 1 },
            ),
            (
                "::1, fd00::1/64",
                TrustedProxiesError::HostBitsSet { position: 2 },
            ),
            (
                "0.0.0.0/0",
                TrustedProxiesError::MatchesEverything { position: 1 },
            ),
            (
                "::/0",
                TrustedProxiesError::MatchesEverything { position: 1 },
            ),
            (
                "::ffff:10.0.0.0/104",
                TrustedProxiesError::MappedIpv4 { position: 1 },
            ),
        ] {
            assert_eq!(TrustedProxies::parse(value), Err(expected), "{value}");
        }
        let too_many = vec!["10.0.0.1"; MAX_TRUSTED_BLOCKS + 1].join(",");
        assert_eq!(
            TrustedProxies::parse(&too_many),
            Err(TrustedProxiesError::TooManyEntries)
        );
    }
}
