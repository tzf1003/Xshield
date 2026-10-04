//! Deterministic destination policy for site upstream (origin) addresses.
//!
//! A site configuration makes the control plane open connections on an
//! operator's behalf (health probes) and makes the edge forward traffic to the
//! same address. Both must refuse destinations that lead into internal,
//! special-purpose or translation-capable networks. The rules live here, in
//! one pure function over a parsed [`IpAddr`], so validation at write time and
//! the re-check at connect time cannot disagree.
//!
//! The classification is by *parsed numeric value*, never by text: a bracketed
//! IPv6 literal, an IPv4-mapped IPv6 literal or a NAT64 form is judged by the
//! address it denotes. Anything that embeds another address family (IPv4
//! mapped, NAT64, 6to4, Teredo) is refused outright instead of being unwrapped,
//! because the embedded IPv4 destination is chosen by whoever writes the
//! literal and a gateway on the path may route it anywhere.

use crate::domain::InvalidValue;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The category under which an upstream destination is refused.
///
/// The variants only describe *why* for tests and operator logs; every refusal
/// is reported to API callers under the single stable code
/// `CONTROL_SITE_SSRF_BLOCKED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRefusal {
    /// `0.0.0.0/8`, `::` and other "this host/network" forms.
    Unspecified,
    /// `127.0.0.0/8` and `::1`, refused unless the deployment opts in.
    Loopback,
    /// RFC 1918 private IPv4 space.
    Private,
    /// RFC 6598 shared address space (carrier-grade NAT).
    SharedAddressSpace,
    /// `169.254.0.0/16` and `fe80::/10`.
    LinkLocal,
    /// `fc00::/7` unique local IPv6 space.
    UniqueLocal,
    /// IPv4 `224.0.0.0/4` and IPv6 `ff00::/8`.
    Multicast,
    /// Reserved, benchmarking, deprecated or otherwise non-routable space.
    Reserved,
    /// RFC 5737, RFC 3849 and RFC 9637 documentation ranges.
    Documentation,
    /// An IPv4-mapped IPv6 literal (`::ffff:0:0/96`).
    Mapped,
    /// NAT64, 6to4 and Teredo forms that embed an IPv4 destination.
    Translation,
    /// A well-known cloud metadata service address.
    CloudMetadata,
}

impl UpstreamRefusal {
    /// Returns a stable lower-case token for logs and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::SharedAddressSpace => "shared_address_space",
            Self::LinkLocal => "link_local",
            Self::UniqueLocal => "unique_local",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
            Self::Documentation => "documentation",
            Self::Mapped => "ipv4_mapped",
            Self::Translation => "translation",
            Self::CloudMetadata => "cloud_metadata",
        }
    }
}

const fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

const fn v6(segments: [u16; 8]) -> u128 {
    let mut value = 0_u128;
    let mut index = 0;
    while index < 8 {
        value = (value << 16) | segments[index] as u128;
        index += 1;
    }
    value
}

/// Individual cloud metadata endpoints. They are checked before the broader
/// ranges so the refusal names what the address is.
const METADATA_V4: [u32; 4] = [
    v4(169, 254, 169, 254), // AWS, GCP, Azure, OpenStack link-local IMDS
    v4(168, 63, 129, 16),   // Azure wire server (a public address)
    v4(100, 100, 100, 200), // Alibaba Cloud
    v4(192, 0, 0, 192),     // Oracle Cloud
];

const METADATA_V6: [u128; 2] = [
    v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]), // AWS IMDS over IPv6
    v6([0xfe80, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe]), // link-local form of 169.254.169.254
];

/// `(base, prefix length, category)`; the first matching entry wins.
const RANGES_V4: [(u32, u8, UpstreamRefusal); 14] = [
    (v4(0, 0, 0, 0), 8, UpstreamRefusal::Unspecified),
    (v4(10, 0, 0, 0), 8, UpstreamRefusal::Private),
    (v4(100, 64, 0, 0), 10, UpstreamRefusal::SharedAddressSpace),
    (v4(169, 254, 0, 0), 16, UpstreamRefusal::LinkLocal),
    (v4(172, 16, 0, 0), 12, UpstreamRefusal::Private),
    (v4(192, 0, 0, 0), 24, UpstreamRefusal::Reserved),
    (v4(192, 0, 2, 0), 24, UpstreamRefusal::Documentation),
    (v4(192, 88, 99, 0), 24, UpstreamRefusal::Reserved),
    (v4(192, 168, 0, 0), 16, UpstreamRefusal::Private),
    (v4(198, 18, 0, 0), 15, UpstreamRefusal::Reserved),
    (v4(198, 51, 100, 0), 24, UpstreamRefusal::Documentation),
    (v4(203, 0, 113, 0), 24, UpstreamRefusal::Documentation),
    (v4(224, 0, 0, 0), 4, UpstreamRefusal::Multicast),
    // Class E and the limited broadcast address.
    (v4(240, 0, 0, 0), 4, UpstreamRefusal::Reserved),
];

/// `(base, prefix length, category)`; the first matching entry wins.
const RANGES_V6: [(u128, u8, UpstreamRefusal); 12] = [
    // IPv4-compatible and other deprecated `::/96` forms; `::` and `::1` are
    // classified before this table is consulted.
    (v6([0, 0, 0, 0, 0, 0, 0, 0]), 96, UpstreamRefusal::Reserved),
    // NAT64 well-known prefix (RFC 6052) and local-use prefix (RFC 8215).
    (
        v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]),
        96,
        UpstreamRefusal::Translation,
    ),
    (
        v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]),
        48,
        UpstreamRefusal::Translation,
    ),
    // Discard-only prefix (RFC 6666).
    (
        v6([0x100, 0, 0, 0, 0, 0, 0, 0]),
        64,
        UpstreamRefusal::Reserved,
    ),
    // Teredo (RFC 4380).
    (
        v6([0x2001, 0, 0, 0, 0, 0, 0, 0]),
        32,
        UpstreamRefusal::Translation,
    ),
    (
        v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0]),
        32,
        UpstreamRefusal::Documentation,
    ),
    // 6to4 (RFC 3056).
    (
        v6([0x2002, 0, 0, 0, 0, 0, 0, 0]),
        16,
        UpstreamRefusal::Translation,
    ),
    (
        v6([0x3fff, 0, 0, 0, 0, 0, 0, 0]),
        20,
        UpstreamRefusal::Documentation,
    ),
    (
        v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]),
        7,
        UpstreamRefusal::UniqueLocal,
    ),
    (
        v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]),
        10,
        UpstreamRefusal::LinkLocal,
    ),
    // Deprecated site-local space (RFC 3879).
    (
        v6([0xfec0, 0, 0, 0, 0, 0, 0, 0]),
        10,
        UpstreamRefusal::Reserved,
    ),
    (
        v6([0xff00, 0, 0, 0, 0, 0, 0, 0]),
        8,
        UpstreamRefusal::Multicast,
    ),
];

fn in_v4(address: u32, base: u32, prefix: u8) -> bool {
    // Prefix lengths in the tables are 1..=32, so the shift never overflows.
    let mask = u32::MAX << (32 - u32::from(prefix));
    address & mask == base & mask
}

fn in_v6(address: u128, base: u128, prefix: u8) -> bool {
    // Prefix lengths in the tables are 1..=128, so the shift never overflows.
    let mask = u128::MAX << (128 - u32::from(prefix));
    address & mask == base & mask
}

fn refuse_v4(address: Ipv4Addr, allow_loopback: bool) -> Option<UpstreamRefusal> {
    let value = u32::from(address);
    if METADATA_V4.contains(&value) {
        return Some(UpstreamRefusal::CloudMetadata);
    }
    if in_v4(value, v4(127, 0, 0, 0), 8) {
        return (!allow_loopback).then_some(UpstreamRefusal::Loopback);
    }
    RANGES_V4
        .iter()
        .find(|(base, prefix, _)| in_v4(value, *base, *prefix))
        .map(|(_, _, refusal)| *refusal)
}

fn refuse_v6(address: Ipv6Addr, allow_loopback: bool) -> Option<UpstreamRefusal> {
    let value = u128::from(address);
    if METADATA_V6.contains(&value) {
        return Some(UpstreamRefusal::CloudMetadata);
    }
    if value == 0 {
        return Some(UpstreamRefusal::Unspecified);
    }
    if value == 1 {
        return (!allow_loopback).then_some(UpstreamRefusal::Loopback);
    }
    RANGES_V6
        .iter()
        .find(|(base, prefix, _)| in_v6(value, *base, *prefix))
        .map(|(_, _, refusal)| *refusal)
}

/// Classifies one upstream destination address.
///
/// Returns `None` only for a destination that is acceptable as a public
/// upstream. `allow_loopback` is the deployment's explicit local-lab opt-in; it
/// permits `127.0.0.0/8` and `::1` and nothing else.
///
/// An IPv4-mapped IPv6 literal is refused rather than unwrapped, so
/// `[::ffff:8.8.8.8]` is rejected even though `8.8.8.8` alone is acceptable:
/// legitimate configurations have no reason to spell an IPv4 origin that way
/// and the notation is the usual way to smuggle an internal IPv4 destination
/// past a textual check.
#[must_use]
pub fn refuse_upstream_ip(address: IpAddr, allow_loopback: bool) -> Option<UpstreamRefusal> {
    match address {
        IpAddr::V4(address) => refuse_v4(address, allow_loopback),
        IpAddr::V6(address) => {
            if address.to_ipv4_mapped().is_some() {
                return Some(UpstreamRefusal::Mapped);
            }
            refuse_v6(address, allow_loopback)
        }
    }
}

/// Classifies the socket address a connection is about to be opened to.
///
/// Call this with the address that will actually be dialled, after any
/// resolution step, so a name that resolved somewhere unexpected is caught at
/// the moment of use as well as at validation time.
#[must_use]
pub fn refuse_upstream_socket(
    address: SocketAddr,
    allow_loopback: bool,
) -> Option<UpstreamRefusal> {
    // `to_canonical` unwraps an IPv4-mapped IPv6 address, so the mapped form is
    // judged both as itself (refused outright) and as the IPv4 it denotes.
    refuse_upstream_ip(address.ip(), allow_loopback)
        .or_else(|| refuse_upstream_ip(address.ip().to_canonical(), allow_loopback))
}

/// Parses a literal `ipv4:port` or `[ipv6]:port` upstream address.
///
/// The host must be an IP literal: the control plane never resolves operator
/// supplied names, so there is no resolution step an attacker could steer.
/// Port 0 is rejected; default ports (80/443) are ordinary values.
///
/// # Errors
/// Returns [`InvalidValue`] for names, missing or zero ports, zone
/// identifiers and anything else that is not a plain socket address literal.
pub fn parse_upstream_socket(address: &str) -> Result<SocketAddr, InvalidValue> {
    let socket = address
        .parse::<SocketAddr>()
        .map_err(|_| InvalidValue::new("upstream_address"))?;
    // A zone identifier ties an address to a local interface; no remote origin
    // is ever reached through one.
    let scoped = matches!(socket, SocketAddr::V6(v6) if v6.scope_id() != 0);
    if socket.port() == 0 || scoped {
        return Err(InvalidValue::new("upstream_address"));
    }
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ipv4_ranges_are_refused_with_their_category_and_boundaries_hold() {
        use UpstreamRefusal::*;
        for (text, expected) in [
            ("0.0.0.0", Some(Unspecified)),
            ("0.255.255.255", Some(Unspecified)),
            ("1.0.0.0", None),
            ("9.255.255.255", None),
            ("10.0.0.0", Some(Private)),
            ("10.255.255.255", Some(Private)),
            ("11.0.0.0", None),
            ("100.63.255.255", None),
            ("100.64.0.0", Some(SharedAddressSpace)),
            ("100.100.100.200", Some(CloudMetadata)),
            ("100.127.255.255", Some(SharedAddressSpace)),
            ("100.128.0.0", None),
            ("126.255.255.255", None),
            ("127.0.0.1", Some(Loopback)),
            ("127.255.255.255", Some(Loopback)),
            ("128.0.0.0", None),
            ("169.253.255.255", None),
            ("169.254.0.0", Some(LinkLocal)),
            ("169.254.169.254", Some(CloudMetadata)),
            ("169.254.255.255", Some(LinkLocal)),
            ("169.255.0.0", None),
            ("168.63.129.16", Some(CloudMetadata)),
            ("168.63.129.17", None),
            ("172.15.255.255", None),
            ("172.16.0.0", Some(Private)),
            ("172.31.255.255", Some(Private)),
            ("172.32.0.0", None),
            ("192.0.0.0", Some(Reserved)),
            ("192.0.0.192", Some(CloudMetadata)),
            ("192.0.0.255", Some(Reserved)),
            ("192.0.1.0", None),
            ("192.0.2.0", Some(Documentation)),
            ("192.0.3.0", None),
            ("192.88.99.1", Some(Reserved)),
            ("192.167.255.255", None),
            ("192.168.0.0", Some(Private)),
            ("192.168.255.255", Some(Private)),
            ("192.169.0.0", None),
            ("198.17.255.255", None),
            ("198.18.0.0", Some(Reserved)),
            ("198.19.255.255", Some(Reserved)),
            ("198.20.0.0", None),
            ("198.51.100.255", Some(Documentation)),
            ("203.0.113.0", Some(Documentation)),
            ("223.255.255.255", None),
            ("224.0.0.0", Some(Multicast)),
            ("239.255.255.255", Some(Multicast)),
            ("240.0.0.0", Some(Reserved)),
            ("255.255.255.255", Some(Reserved)),
            ("8.8.8.8", None),
            ("1.1.1.1", None),
        ] {
            assert_eq!(refuse_upstream_ip(ip(text), false), expected, "{text}");
        }
    }

    #[test]
    fn ipv6_ranges_are_refused_with_their_category() {
        use UpstreamRefusal::*;
        for (text, expected) in [
            ("::", Some(Unspecified)),
            ("::1", Some(Loopback)),
            ("::2", Some(Reserved)),
            ("::127.0.0.1", Some(Reserved)),
            ("::ffff:8.8.8.8", Some(Mapped)),
            ("::ffff:127.0.0.1", Some(Mapped)),
            ("::ffff:169.254.169.254", Some(Mapped)),
            ("64:ff9b::7f00:1", Some(Translation)),
            ("64:ff9b::808:808", Some(Translation)),
            ("64:ff9b:1::1", Some(Translation)),
            ("100::1", Some(Reserved)),
            ("2001::1", Some(Translation)),
            ("2001:db8::1", Some(Documentation)),
            ("2001:4860:4860::8888", None),
            ("2002:7f00:1::", Some(Translation)),
            ("2606:4700:4700::1111", None),
            ("3fff::1", Some(Documentation)),
            ("fc00::1", Some(UniqueLocal)),
            ("fd00::1", Some(UniqueLocal)),
            ("fd00:ec2::254", Some(CloudMetadata)),
            ("fe80::1", Some(LinkLocal)),
            ("fe80::a9fe:a9fe", Some(CloudMetadata)),
            ("febf::1", Some(LinkLocal)),
            ("fec0::1", Some(Reserved)),
            ("ff02::1", Some(Multicast)),
        ] {
            assert_eq!(refuse_upstream_ip(ip(text), false), expected, "{text}");
        }
    }

    #[test]
    fn loopback_opt_in_unlocks_only_loopback() {
        assert_eq!(refuse_upstream_ip(ip("127.0.0.1"), true), None);
        assert_eq!(refuse_upstream_ip(ip("127.9.9.9"), true), None);
        assert_eq!(refuse_upstream_ip(ip("::1"), true), None);
        for text in [
            "10.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "fd00::1",
        ] {
            assert!(
                refuse_upstream_ip(ip(text), true).is_some(),
                "{text} stays refused with the loopback opt-in"
            );
        }
    }

    #[test]
    fn socket_check_judges_the_canonical_address_as_well() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
        assert_eq!(
            refuse_upstream_socket(mapped, true),
            Some(UpstreamRefusal::Mapped),
            "a mapped loopback is never unlocked by the loopback opt-in"
        );
        let public: SocketAddr = "8.8.8.8:80".parse().unwrap();
        assert_eq!(refuse_upstream_socket(public, false), None);
    }

    #[test]
    fn parse_requires_a_literal_socket_with_a_nonzero_port() {
        assert_eq!(
            parse_upstream_socket("8.8.8.8:80").unwrap().port(),
            80,
            "default ports are ordinary values"
        );
        assert_eq!(
            parse_upstream_socket("[2001:4860:4860::8888]:443")
                .unwrap()
                .port(),
            443
        );
        for bad in [
            "8.8.8.8",
            "8.8.8.8:0",
            "8.8.8.8:65536",
            "8.8.8.8:+80",
            "8.8.8.8: 80",
            " 8.8.8.8:80",
            "example.com:80",
            "localhost:80",
            "[::1]",
            "::1:80",
            "[fe80::1%eth0]:80",
            "[2001:4860:4860::8888%1]:80",
            "08.8.8.8:80",
            "8.8.8:80",
            "",
        ] {
            assert!(parse_upstream_socket(bad).is_err(), "{bad:?}");
        }
    }
}
