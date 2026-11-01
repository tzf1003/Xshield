//! Assembles the Pingora server around an [`EdgeProxy`].

use std::error::Error;

use pingora::listeners::tls::TlsSettings;
use pingora::prelude::{Opt, Server, http_proxy_service};
use xshield_judge::jev::JevPort;

use crate::proxy::EdgeProxy;

/// Builds a server listening on `addresses` (`host:port`), with TLS on every
/// listener when `tls` names a certificate and key file.
///
/// `options` is `None` for the real process, which reads the command line;
/// tests pass `Some(Opt::default())`.
///
/// # Errors
/// Pingora's error when the server or a certificate cannot be set up.
pub fn build_server<J: JevPort + 'static>(
    proxy: EdgeProxy<J>,
    addresses: &[String],
    tls: Option<&(String, String)>,
    options: Option<Opt>,
) -> Result<Server, Box<dyn Error>> {
    let mut server = Server::new(options)?;
    server.bootstrap();
    let mut service = http_proxy_service(&server.configuration, proxy);
    for address in addresses {
        if let Some((cert, key)) = tls {
            let mut settings = TlsSettings::intermediate(cert, key)?;
            settings.enable_h2();
            service.add_tls_with_settings(address, None, settings);
        } else {
            service.add_tcp(address);
        }
    }
    server.add_service(service);
    Ok(server)
}
