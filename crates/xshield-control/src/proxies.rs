//! The reverse proxies whose `X-Forwarded-For` the control plane believes
//! (`XSHIELD_CONTROL_TRUSTED_PROXIES`, docs/03 section 3.3).
//!
//! The failed sign-in limit counts per client address. Behind a reverse proxy every
//! connection comes from the proxy, so without this list all clients would share one
//! count, and ten wrong passwords from anyone would lock the administrator out. The
//! header is believed only on a connection from a listed proxy: a client that
//! connects directly cannot choose the address it is counted under.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// One trusted network: an address and the number of leading bits that must match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address = address.parse::<IpAddr>().ok()?.to_canonical();
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().ok().filter(|prefix| *prefix <= bits)?,
            None => bits,
        };
        Some(Self { address, prefix })
    }

    fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                leading_bits_match(&network.octets(), &candidate.octets(), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                leading_bits_match(&network.octets(), &candidate.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Whether the first `prefix` bits of `left` and `right` are equal.
fn leading_bits_match(left: &[u8], right: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let rest = prefix % 8;
    if left.get(..whole) != right.get(..whole) {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xff_u8 << (8 - rest);
    match (left.get(whole), right.get(whole)) {
        (Some(left), Some(right)) => left & mask == right & mask,
        _ => false,
    }
}

/// The proxies in front of the control plane. Empty by default: the client is then
/// always the peer of the connection, and `X-Forwarded-For` is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Network>);

impl TrustedProxies {
    /// Parses a comma-separated list of addresses and CIDR networks, such as
    /// `127.0.0.1, 10.0.0.0/8, fd00::/8`. An empty text is an empty list.
    ///
    /// # Errors
    /// The item that is neither an address nor a network.
    pub fn parse(text: &str) -> Result<Self, String> {
        text.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| Network::parse(item).ok_or_else(|| item.to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    fn contains(&self, address: IpAddr) -> bool {
        self.0.iter().any(|network| network.contains(address))
    }

    /// The address a request is counted under. For a connection from a trusted
    /// proxy it is the last `X-Forwarded-For` entry that is not itself a trusted
    /// proxy: entries further left are whatever the client sent. An entry that is
    /// not an address ends the walk, so nothing to its left is believed. In every
    /// other case it is `peer`.
    #[must_use]
    pub fn client_address(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.contains(peer) {
            return peer;
        }
        let mut client = peer;
        let entries = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .collect::<Vec<_>>();
        for entry in entries.into_iter().rev() {
            let Ok(address) = entry.trim().parse::<IpAddr>() else {
                break;
            };
            client = address.to_canonical();
            if !self.contains(client) {
                break;
            }
        }
        client
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn forwarded(values: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn a_list_holds_addresses_and_networks_and_refuses_anything_else() {
        let proxies = TrustedProxies::parse(" 127.0.0.1, 10.0.0.0/8 ,fd00::/8,").expect("valid");
        assert!(proxies.contains(address("127.0.0.1")));
        assert!(!proxies.contains(address("127.0.0.2")));
        assert!(proxies.contains(address("10.255.0.9")));
        assert!(!proxies.contains(address("11.0.0.1")));
        assert!(proxies.contains(address("fd12::1")));
        assert!(!proxies.contains(address("fe80::1")));
        assert_eq!(TrustedProxies::parse(""), Ok(TrustedProxies::default()));
        for bad in [
            "proxy.local",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/x",
            "/8",
        ] {
            assert_eq!(TrustedProxies::parse(bad), Err(bad.to_owned()), "{bad}");
        }
    }

    #[test]
    fn a_prefix_that_ends_inside_a_byte_compares_only_its_bits() {
        let proxies = TrustedProxies::parse("172.16.0.0/12").expect("valid");
        assert!(proxies.contains(address("172.31.255.255")));
        assert!(!proxies.contains(address("172.32.0.0")));
        let all = TrustedProxies::parse("0.0.0.0/0").expect("valid");
        assert!(all.contains(address("203.0.113.9")));
        assert!(!all.contains(address("::1")));
    }

    #[test]
    fn without_trusted_proxies_the_header_is_ignored() {
        let proxies = TrustedProxies::default();
        let headers = forwarded(&["198.51.100.7"]);
        assert_eq!(
            proxies.client_address(address("203.0.113.9"), &headers),
            address("203.0.113.9")
        );
    }

    #[test]
    fn a_direct_client_cannot_choose_its_address() {
        let proxies = TrustedProxies::parse("10.0.0.1").expect("valid");
        let headers = forwarded(&["198.51.100.7"]);
        assert_eq!(
            proxies.client_address(address("203.0.113.9"), &headers),
            address("203.0.113.9")
        );
    }

    #[test]
    fn behind_a_trusted_proxy_the_client_is_the_last_untrusted_entry() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").expect("valid");
        let peer = address("10.0.0.1");
        // The client put 192.0.2.1 there itself; the proxy appended what it saw.
        assert_eq!(
            proxies.client_address(peer, &forwarded(&["192.0.2.1, 198.51.100.7"])),
            address("198.51.100.7")
        );
        // Two proxies in a row, and the header split over two lines.
        assert_eq!(
            proxies.client_address(peer, &forwarded(&["192.0.2.1", "198.51.100.7, 10.0.0.2"])),
            address("198.51.100.7")
        );
        // An IPv4 peer that arrives on a dual-stack socket is still the proxy.
        assert_eq!(
            proxies.client_address(address("::ffff:10.0.0.1"), &forwarded(&["198.51.100.7"])),
            address("198.51.100.7")
        );
    }

    #[test]
    fn a_missing_or_unreadable_header_leaves_the_nearest_known_address() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").expect("valid");
        let peer = address("10.0.0.1");
        assert_eq!(proxies.client_address(peer, &HeaderMap::new()), peer);
        assert_eq!(proxies.client_address(peer, &forwarded(&["unknown"])), peer);
        // Nothing left of an unreadable entry is believed.
        assert_eq!(
            proxies.client_address(peer, &forwarded(&["198.51.100.7, unknown, 10.0.0.2"])),
            address("10.0.0.2")
        );
    }
}
