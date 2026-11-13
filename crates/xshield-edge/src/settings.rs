//! Deployment settings read from the environment (docs/03 section 3.3).

use std::path::PathBuf;

/// Everything the edge needs from its environment, except the Jev client
/// (see `xshield_judge::jev::environment_settings`).
#[derive(Debug, PartialEq, Eq)]
pub struct Settings {
    /// TCP ports to listen on (all interfaces).
    pub ports: Vec<u16>,
    /// Certificate and key files; when set every port speaks TLS.
    pub tls: Option<(String, String)>,
    /// Control plane database: sites are read from it and decisions written to it.
    pub database_url: Option<String>,
    /// Development alternative to the database: a JSON array of site specs.
    pub sites_file: Option<PathBuf>,
    /// Secret for the context hashes, at least 32 bytes.
    pub context_key: Vec<u8>,
}

impl Settings {
    /// Reads the process environment.
    ///
    /// # Errors
    /// A message naming the offending variable.
    pub fn from_environment() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Reads settings through `lookup`, which returns a variable's value.
    ///
    /// # Errors
    /// A message naming the offending variable.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let ports = lookup("XSHIELD_EDGE_LISTEN_PORTS")
            .ok_or("XSHIELD_EDGE_LISTEN_PORTS is required (comma separated ports)")?
            .split(',')
            .map(str::trim)
            .filter(|port| !port.is_empty())
            .map(|port| {
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| format!("XSHIELD_EDGE_LISTEN_PORTS: bad port {port:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if ports.is_empty() {
            return Err("XSHIELD_EDGE_LISTEN_PORTS names no port".to_owned());
        }
        let tls = match (
            lookup("XSHIELD_EDGE_TLS_CERT_PATH"),
            lookup("XSHIELD_EDGE_TLS_KEY_PATH"),
        ) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (None, None) => None,
            _ => {
                return Err(
                    "XSHIELD_EDGE_TLS_CERT_PATH and XSHIELD_EDGE_TLS_KEY_PATH go together"
                        .to_owned(),
                );
            }
        };
        let database_url = lookup("XSHIELD_DATABASE_URL").filter(|value| !value.is_empty());
        let sites_file = lookup("XSHIELD_EDGE_SITES_FILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        if database_url.is_none() && sites_file.is_none() {
            return Err(
                "set XSHIELD_DATABASE_URL (or XSHIELD_EDGE_SITES_FILE for development)".to_owned(),
            );
        }
        let key_hex =
            lookup("XSHIELD_CONTEXT_KEY_HEX").ok_or("XSHIELD_CONTEXT_KEY_HEX is required")?;
        let context_key = decode_hex(&key_hex)
            .filter(|key| key.len() >= 32)
            .ok_or("XSHIELD_CONTEXT_KEY_HEX must be at least 64 hex digits")?;
        Ok(Self {
            ports,
            tls,
            database_url,
            sites_file,
            context_key,
        })
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().as_bytes();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn minimal_development_settings() {
        let settings = Settings::from_lookup(lookup(&[
            ("XSHIELD_EDGE_LISTEN_PORTS", "8080, 8443"),
            ("XSHIELD_EDGE_SITES_FILE", "/tmp/sites.json"),
            ("XSHIELD_CONTEXT_KEY_HEX", KEY),
        ]))
        .expect("valid");
        assert_eq!(settings.ports, vec![8080, 8443]);
        assert_eq!(settings.context_key.len(), 32);
        assert!(settings.tls.is_none() && settings.database_url.is_none());
    }

    #[test]
    fn refuses_bad_input() {
        let base = [
            ("XSHIELD_EDGE_LISTEN_PORTS", "8080"),
            ("XSHIELD_DATABASE_URL", "postgres://x"),
            ("XSHIELD_CONTEXT_KEY_HEX", KEY),
        ];
        assert!(Settings::from_lookup(lookup(&base)).is_ok());
        for (name, value) in [
            ("XSHIELD_EDGE_LISTEN_PORTS", "0"),
            ("XSHIELD_EDGE_LISTEN_PORTS", "abc"),
            ("XSHIELD_CONTEXT_KEY_HEX", "abcd"),
            ("XSHIELD_CONTEXT_KEY_HEX", "zz"),
            ("XSHIELD_EDGE_TLS_CERT_PATH", "/c.pem"),
        ] {
            let mut pairs = base.to_vec();
            pairs.retain(|(k, _)| *k != name);
            pairs.push((name, value));
            assert!(
                Settings::from_lookup(lookup(&pairs)).is_err(),
                "{name}={value}"
            );
        }
        let no_source = [base[0], base[2]];
        assert!(Settings::from_lookup(lookup(&no_source)).is_err());
    }
}
