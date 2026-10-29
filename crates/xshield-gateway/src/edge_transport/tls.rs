//! Edge certificates, their TLS acceptor profile, SNI selection and reloads.
//!
//! Profile: Mozilla "intermediate" v5 (TLS 1.2 with AEAD ECDHE/DHE suites,
//! TLS 1.3), an explicit TLS 1.2 floor, ALPN `h2` then `http/1.1`, no
//! renegotiation and no session tickets. OpenSSL generates the ticket key once
//! per process and never rotates it, so tickets would let anyone who obtains
//! that key decrypt every resumed session for the process lifetime; stateful
//! resumption from OpenSSL's bounded in-memory session cache is kept instead.
//!
//! Certificates. The primary pair serves every handshake whose SNI matches no
//! additional certificate, including handshakes without SNI. Each additional
//! pair serves the DNS names of its leaf (subject alternative names, or the
//! common name when there are none); a wildcard name covers exactly one label.
//! SNI only chooses the certificate: routing stays on Host/`:authority`, so a
//! client naming one site in SNI and another in Host is routed by Host as
//! before. Every pair gets the same profile, because OpenSSL takes protocol
//! callbacks such as ALPN from the context selected for the handshake.
//!
//! Reloads. The files are re-read when their metadata changes. A complete,
//! valid set replaces the acceptor for new handshakes only; established
//! connections keep the certificate they negotiated. Anything less (a missing
//! file, a key that does not match yet, an expired leaf) leaves the current
//! certificates in place, is counted, and is retried on the next change.
//!
//! Additional certificates, add and remove. Besides the fixed pairs named by
//! [`super::TLS_SNI_CERTS_ENV`] (which, like the primary pair's own
//! variables, are read once at startup), a directory named by
//! [`super::TLS_SNI_CERTS_DIR_ENV`] is rescanned on every reload tick: each
//! immediate subdirectory holding exactly `tls.crt` and `tls.key` (the names
//! a Kubernetes `kubernetes.io/tls` secret mounts) is one additional pair,
//! keyed by its own leaf's DNS names, never by the subdirectory's name.
//! Creating or deleting a subdirectory therefore adds or removes a
//! certificate without a restart, on the same schedule and under the same
//! all-or-nothing validation as a content rotation; a subdirectory created
//! but not yet fully written (secret volumes populate `tls.crt` and
//! `tls.key` separately) is simply the same "not current yet" case the
//! content reload already retries.

use super::{
    TLS_CERT_PATH_ENV, TLS_KEY_PATH_ENV, TLS_SNI_CERTS_DIR_ENV, TransportConfigError, read_pem_file,
};
// The same openssl crate Pingora's TLS layer is built on (one version in the
// lock file), so these are the types `pingora::protocols::tls` accepts.
use openssl::{
    asn1::Asn1Time,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{
        AlpnError, NameType, SniError, SslAcceptor, SslAcceptorBuilder, SslAlert, SslContext,
        SslMethod, SslOptions, SslRef, SslVersion, select_next_proto,
    },
    x509::X509,
};
use std::{
    cmp::Ordering,
    collections::HashMap,
    ffi::OsString,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError, RwLock},
};

/// The two files one additional-certificate subdirectory must hold, named as
/// a Kubernetes TLS secret mounts them.
const DIR_CERT_FILE: &str = "tls.crt";
const DIR_KEY_FILE: &str = "tls.key";

/// Server ALPN preference in wire format: HTTP/2, then HTTP/1.1.
const ALPN_PREFERENCE: &[u8] = b"\x02h2\x08http/1.1";

/// One certificate chain and its key, with the variables that named them.
#[derive(Clone, Debug)]
pub(super) struct CertificateSource {
    certificate_variable: &'static str,
    key_variable: &'static str,
    certificate: PathBuf,
    key: PathBuf,
}

impl CertificateSource {
    /// The pair named by the primary certificate and key variables.
    pub(super) const fn primary(certificate: PathBuf, key: PathBuf) -> Self {
        Self {
            certificate_variable: TLS_CERT_PATH_ENV,
            key_variable: TLS_KEY_PATH_ENV,
            certificate,
            key,
        }
    }

    /// A pair listed in `variable`, which names both files.
    pub(super) const fn additional(
        variable: &'static str,
        certificate: PathBuf,
        key: PathBuf,
    ) -> Self {
        Self {
            certificate_variable: variable,
            key_variable: variable,
            certificate,
            key,
        }
    }
}

/// What a file looked like when it was last read: enough to notice an
/// in-place rewrite, a rename over it, or a symlink swap (Kubernetes secret
/// volumes), none of which keeps all of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

/// One directory entry's name and the stamps of its `tls.crt`/`tls.key`.
type DirectoryEntryStamps = (OsString, Option<FileStamp>, Option<FileStamp>);

/// One stamp per statically configured file, in a fixed order, plus the
/// directory-discovered pairs (name, certificate stamp, key stamp) in
/// directory order; `Err` when the directory itself could not be listed.
/// Any difference from the previous attempt (a changed stamp, a pair
/// appearing or disappearing, the directory becoming readable or not)
/// triggers a reload attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Fingerprint {
    files: Vec<Option<FileStamp>>,
    directory: Option<Result<Vec<DirectoryEntryStamps>, ()>>,
}

fn stamp(path: &Path) -> Option<FileStamp> {
    std::fs::metadata(path).ok().map(|metadata| FileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}

/// Immediate subdirectories of `directory`, sorted by name; a symlink to a
/// directory (as a Kubernetes secret volume mounts one) counts.
fn list_subdirectories(directory: &Path) -> Result<Vec<(OsString, PathBuf)>, ()> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        if std::fs::metadata(entry.path()).is_ok_and(|metadata| metadata.is_dir()) {
            found.push((entry.file_name(), entry.path()));
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found)
}

fn directory_fingerprint(directory: &Path) -> Result<Vec<DirectoryEntryStamps>, ()> {
    Ok(list_subdirectories(directory)?
        .into_iter()
        .map(|(name, path)| {
            let certificate = stamp(&path.join(DIR_CERT_FILE));
            let key = stamp(&path.join(DIR_KEY_FILE));
            (name, certificate, key)
        })
        .collect())
}

/// One additional pair per immediate subdirectory of `directory`, in
/// directory order.
fn directory_sources(directory: &Path) -> Result<Vec<CertificateSource>, TransportConfigError> {
    let entries = list_subdirectories(directory).map_err(|()| {
        TransportConfigError::SniCertsDirUnreadable {
            path: directory.to_path_buf(),
        }
    })?;
    Ok(entries
        .into_iter()
        .map(|(_, path)| {
            CertificateSource::additional(
                TLS_SNI_CERTS_DIR_ENV,
                path.join(DIR_CERT_FILE),
                path.join(DIR_KEY_FILE),
            )
        })
        .collect())
}

/// Every configured pair: the primary, the pairs fixed at startup, and the
/// directory rescanned on every reload.
#[derive(Clone, Debug)]
pub(super) struct TlsSources {
    primary: CertificateSource,
    fixed_additional: Vec<CertificateSource>,
    directory: Option<PathBuf>,
}

impl TlsSources {
    pub(super) fn new(
        primary: CertificateSource,
        fixed_additional: Vec<CertificateSource>,
        directory: Option<PathBuf>,
    ) -> Self {
        Self {
            primary,
            fixed_additional,
            directory,
        }
    }

    /// The pairs fixed at startup together with whatever the directory holds
    /// right now; `None` directory entries need a restart to go away, so
    /// this is the only part that can change between two calls.
    fn additional(&self) -> Result<Vec<CertificateSource>, TransportConfigError> {
        let mut additional = self.fixed_additional.clone();
        if let Some(directory) = &self.directory {
            additional.extend(directory_sources(directory)?);
        }
        Ok(additional)
    }

    fn fingerprint(&self) -> Fingerprint {
        let files = std::iter::once(&self.primary)
            .chain(&self.fixed_additional)
            .flat_map(|source| [&source.certificate, &source.key])
            .map(|path| stamp(path))
            .collect();
        let directory = self.directory.as_deref().map(directory_fingerprint);
        Fingerprint { files, directory }
    }

    /// Loads, validates and cross-checks every pair, then builds the
    /// acceptor and counts it was built from (the primary included).
    /// Nothing is logged; errors name variables and paths only.
    fn load(&self) -> Result<(SslAcceptor, usize), TransportConfigError> {
        let additional = self.additional()?;
        let certificate_count = 1 + additional.len();
        let primary = LoadedPair::load(&self.primary)?;
        let additional = additional
            .iter()
            .map(LoadedPair::load)
            .collect::<Result<Vec<_>, _>>()?;
        let mut by_name = HashMap::new();
        for name in &primary.names {
            by_name.insert(name.clone(), None);
        }
        for pair in &additional {
            if pair.names.is_empty() {
                return Err(TransportConfigError::NoCertificateNames {
                    variable: pair.source.certificate_variable,
                    path: pair.source.certificate.clone(),
                });
            }
            let context = pair.builder()?.build().into_context();
            for name in &pair.names {
                if by_name
                    .insert(name.clone(), Some(context.clone()))
                    .is_some()
                {
                    return Err(TransportConfigError::DuplicateCertificateName {
                        name: name.clone(),
                    });
                }
            }
        }
        // Names of the primary certificate need no switch: it is already the
        // handshake's context.
        let by_name: HashMap<String, SslContext> = by_name
            .into_iter()
            .filter_map(|(name, context)| Some((name, context?)))
            .collect();
        let mut builder = primary.builder()?;
        if !by_name.is_empty() {
            builder.set_servername_callback(move |ssl: &mut SslRef, _: &mut SslAlert| {
                let selected = ssl
                    .servername(NameType::HOST_NAME)
                    .and_then(|name| select(&by_name, name));
                if let Some(context) = selected {
                    ssl.set_ssl_context(context)
                        .map_err(|_| SniError::ALERT_FATAL)?;
                }
                Ok(())
            });
        }
        Ok((builder.build(), certificate_count))
    }
}

/// The context for a client's SNI: an exact name first, then a wildcard for
/// its first label. `None` keeps the primary certificate.
fn select<'a>(
    by_name: &'a HashMap<String, SslContext>,
    server_name: &str,
) -> Option<&'a SslContext> {
    let name = normalize(server_name);
    by_name.get(&name).or_else(|| {
        let (_, parent) = name.split_once('.')?;
        by_name.get(&format!("*.{parent}"))
    })
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// One validated chain and key, with the DNS names its leaf covers.
struct LoadedPair<'a> {
    source: &'a CertificateSource,
    leaf: X509,
    intermediates: Vec<X509>,
    key: PKey<Private>,
    names: Vec<String>,
}

impl<'a> LoadedPair<'a> {
    fn load(source: &'a CertificateSource) -> Result<Self, TransportConfigError> {
        let invalid_certificate = || TransportConfigError::InvalidCertificate {
            variable: source.certificate_variable,
            path: source.certificate.clone(),
        };
        let invalid_key = || TransportConfigError::InvalidPrivateKey {
            variable: source.key_variable,
            path: source.key.clone(),
        };
        let chain = read_pem_file(source.certificate_variable, &source.certificate, false)?;
        let mut chain = X509::stack_from_pem(&chain)
            .map_err(|_| invalid_certificate())?
            .into_iter();
        let leaf = chain.next().ok_or_else(invalid_certificate)?;
        let now = Asn1Time::days_from_now(0).map_err(|_| TransportConfigError::TlsBackend)?;
        let current = leaf.not_before().compare(&now).ok() != Some(Ordering::Greater)
            && leaf.not_after().compare(&now).ok() == Some(Ordering::Greater);
        if !current {
            return Err(TransportConfigError::CertificateNotCurrentlyValid {
                variable: source.certificate_variable,
                path: source.certificate.clone(),
            });
        }
        let key_pem = read_pem_file(source.key_variable, &source.key, true)?;
        let key = PKey::private_key_from_pem(&key_pem).map_err(|_| invalid_key())?;
        drop(key_pem);
        // Checked explicitly so a key from another pair is reported as such
        // rather than as an unusable key.
        if !leaf
            .public_key()
            .is_ok_and(|certified| certified.public_eq(&key))
        {
            return Err(TransportConfigError::KeyMismatch {
                variable: source.key_variable,
                path: source.certificate.clone(),
            });
        }
        let names = dns_names(&leaf);
        Ok(Self {
            source,
            leaf,
            intermediates: chain.collect(),
            key,
            names,
        })
    }

    /// An acceptor builder with this pair and the edge profile.
    fn builder(&self) -> Result<SslAcceptorBuilder, TransportConfigError> {
        let invalid_certificate = || TransportConfigError::InvalidCertificate {
            variable: self.source.certificate_variable,
            path: self.source.certificate.clone(),
        };
        let backend = |_| TransportConfigError::TlsBackend;
        let mut builder =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).map_err(backend)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(backend)?;
        builder.set_options(SslOptions::NO_TICKET | SslOptions::NO_RENEGOTIATION);
        builder.set_alpn_select_callback(select_alpn);
        builder
            .set_certificate(&self.leaf)
            .map_err(|_| invalid_certificate())?;
        for intermediate in &self.intermediates {
            builder
                .add_extra_chain_cert(intermediate.clone())
                .map_err(|_| invalid_certificate())?;
        }
        builder.set_private_key(&self.key).map_err(|_| {
            TransportConfigError::InvalidPrivateKey {
                variable: self.source.key_variable,
                path: self.source.key.clone(),
            }
        })?;
        builder
            .check_private_key()
            .map_err(|_| TransportConfigError::KeyMismatch {
                variable: self.source.key_variable,
                path: self.source.certificate.clone(),
            })?;
        Ok(builder)
    }
}

/// The leaf's DNS subject alternative names, or its common names when it
/// has none, normalized for lookup.
fn dns_names(leaf: &X509) -> Vec<String> {
    let mut names: Vec<String> = leaf
        .subject_alt_names()
        .map(|alternatives| {
            alternatives
                .iter()
                .filter_map(|name| name.dnsname().map(normalize))
                .collect()
        })
        .unwrap_or_default();
    if names.is_empty() {
        names = leaf
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .filter_map(|entry| entry.data().to_string().ok().map(|name| normalize(&name)))
            .collect();
    }
    names.retain(|name| !name.is_empty());
    names.sort();
    names.dedup();
    names
}

/// Picks `h2` when offered, else `http/1.1`; with neither (or an empty list)
/// the handshake continues without ALPN and the connection speaks HTTP/1.1.
fn select_alpn<'a>(_: &mut SslRef, offered: &'a [u8]) -> Result<&'a [u8], AlpnError> {
    if offered.is_empty() {
        return Err(AlpnError::NOACK);
    }
    select_next_proto(ALPN_PREFERENCE, offered).ok_or(AlpnError::NOACK)
}

/// Validated certificates as loaded at startup.
#[derive(Clone)]
pub(super) struct TlsSettings {
    sources: TlsSources,
    fingerprint: Fingerprint,
    acceptor: SslAcceptor,
    certificates: usize,
}

impl TlsSettings {
    /// Loads every pair; any refusal stops startup.
    pub(super) fn load(sources: TlsSources) -> Result<Self, TransportConfigError> {
        // Taken before reading so a change during the read is seen again.
        let fingerprint = sources.fingerprint();
        let (acceptor, certificates) = sources.load()?;
        Ok(Self {
            sources,
            fingerprint,
            acceptor,
            certificates,
        })
    }

    /// Configured certificate/key pairs, the primary included.
    pub(super) const fn certificates(&self) -> usize {
        self.certificates
    }
}

/// What [`ReloadableTls::reload`] did.
pub(super) enum Reload {
    /// No configured file changed since the last attempt.
    Unchanged,
    /// New handshakes use the files as they are now.
    Replaced,
    /// The files changed but were refused; the previous acceptor stays.
    Refused(TransportConfigError),
}

/// The acceptor new handshakes use, replaced as a whole on a valid reload.
pub(super) struct ReloadableTls {
    sources: TlsSources,
    /// Metadata of the last attempt, held for the whole attempt so reloads
    /// never interleave.
    attempted: Mutex<Fingerprint>,
    current: RwLock<(SslAcceptor, usize)>,
}

impl ReloadableTls {
    pub(super) fn new(settings: TlsSettings) -> Self {
        Self {
            sources: settings.sources,
            attempted: Mutex::new(settings.fingerprint),
            current: RwLock::new((settings.acceptor, settings.certificates)),
        }
    }

    /// The acceptor for a new handshake (a reference-count increment).
    pub(super) fn acceptor(&self) -> SslAcceptor {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .clone()
    }

    /// Certificate/key pairs the acceptor currently in service was built
    /// from, the primary included; reflects the last successful reload, not
    /// necessarily what the directory holds between reload ticks.
    pub(super) fn certificates(&self) -> usize {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .1
    }

    /// Re-reads the files, and rescans the additional-certificate directory,
    /// when anything changed since the last attempt.
    pub(super) fn reload(&self) -> Reload {
        let mut attempted = self
            .attempted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let fingerprint = self.sources.fingerprint();
        if *attempted == fingerprint {
            return Reload::Unchanged;
        }
        *attempted = fingerprint;
        match self.sources.load() {
            Ok(loaded) => {
                *self.current.write().unwrap_or_else(PoisonError::into_inner) = loaded;
                Reload::Replaced
            }
            Err(error) => Reload::Refused(error),
        }
    }
}
