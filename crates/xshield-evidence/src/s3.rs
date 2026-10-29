//! Encrypted evidence objects in an S3-compatible bucket, optionally under
//! S3 Object Lock.
//!
//! The objects are byte-for-byte those of [`crate::LocalEvidenceVault`]: the
//! same AEAD envelope, typed manifest and manifest HMAC, keyed by tenant and
//! site under a configurable prefix. Only the storage differs:
//!
//! - Writes are conditional (`If-None-Match: *`), so any number of gateway
//!   or control instances may write to one bucket; nothing is overwritten and
//!   no local lock or single-writer root is needed.
//! - With object lock configured, the ciphertext and both sidecars are locked
//!   until the manifest's `expires_at`, so neither an operator credential nor
//!   a compromised writer can delete or replace evidence early. Retention
//!   deletes exactly the version it read and verified, so a versioned bucket
//!   never keeps expired ciphertext behind a delete marker.
//! - Opening the vault probes the bucket and fails closed when object lock
//!   is requested but the bucket was not created with it.
//!
//! Like the local vault, the ciphertext is published before its manifest; a
//! crash in between leaves an unreachable orphan that the retention pass may
//! remove once it is older than the orphan grace and no longer locked.

mod client;
mod env;
mod sigv4;
#[cfg(test)]
mod tests;

use crate::{
    EvidenceError, EvidenceKey, EvidenceManifest, EvidenceOrphanCandidate, EvidencePurgeOutcome,
    EvidenceWrite, LocalEvidenceVault, MANIFEST_BYTES_MAX, MAX_SINGLE_ENVELOPE_BYTES, NONCE_BYTES,
    TAG_BYTES, VerifiedEvidenceManifest, decode_authenticated_manifest, hide_absence, lower_hex,
    open_envelope, read_private_bounded, seal, validate_artifact_id, validate_manifest,
    validate_manifest_fields, validate_vault_policy,
};
use chrono::{DateTime, Utc};
use client::S3Client;
use openssl::sha::sha256;
use std::{fmt, io, time::Duration};
use url::Url;
use xshield_core::domain::{SiteId, TenantId};
use zeroize::Zeroizing;

const PREFIX_BYTES_MAX: usize = 256;
const REQUEST_TIMEOUT_MAX: Duration = Duration::from_mins(5);
/// Keys an orphan scan may examine in one call, matching the local vault's
/// directory-entry ceiling.
const SCAN_KEYS_MAX: usize = 100_000;

/// How requests name the bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3Addressing {
    /// `https://endpoint/bucket/key`; required by most self-hosted services.
    Path,
    /// `https://bucket.endpoint/key`; the AWS default.
    VirtualHosted,
}

/// S3 Object Lock retention mode applied to every evidence object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3ObjectLockMode {
    /// Users with `s3:BypassGovernanceRetention` may still delete early.
    Governance,
    /// No principal, including the account root, can delete before expiry.
    Compliance,
}

/// Durable result of one [`S3EvidenceVault::migrate_from_local`] attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceMigrationOutcome {
    /// The ciphertext and both sidecars were newly written to the bucket.
    Migrated,
    /// The bucket already held this artifact; every write was a no-op.
    AlreadyMigrated,
}

/// Static credentials for `SigV4` signing. The secret and session token are
/// zeroized on drop and never formatted.
pub struct S3Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl S3Credentials {
    /// Validates the credential shape without contacting the service.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConfig`] for empty or non-printable values.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: Zeroizing<String>,
        session_token: Option<Zeroizing<String>>,
    ) -> Result<Self, EvidenceError> {
        let access_key_id = access_key_id.into();
        let printable = |value: &str| {
            !value.is_empty()
                && value.len() <= 4096
                && value.bytes().all(|byte| byte.is_ascii_graphic())
        };
        if !printable(&access_key_id)
            || !printable(&secret_access_key)
            || session_token
                .as_deref()
                .is_some_and(|token| !printable(token))
        {
            return Err(EvidenceError::InvalidConfig);
        }
        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
}

impl fmt::Debug for S3Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// Validated location of one evidence bucket.
#[derive(Debug)]
pub struct S3EvidenceStoreConfig {
    scheme: &'static str,
    authority: String,
    region: String,
    bucket: String,
    prefix: String,
    addressing: S3Addressing,
    credentials: S3Credentials,
    object_lock: Option<S3ObjectLockMode>,
    allow_plain_http: bool,
    request_timeout: Duration,
}

/// Unvalidated settings for [`S3EvidenceStoreConfig::new`].
pub struct S3EvidenceStoreSettings<'a> {
    /// `https://host[:port]` with no path, query or user info.
    pub endpoint: &'a str,
    /// `SigV4` region, such as `us-east-1`.
    pub region: &'a str,
    /// Bucket name per the S3 naming rules.
    pub bucket: &'a str,
    /// Empty, or `/`-separated segments ending in `/`, prepended to every key.
    pub prefix: &'a str,
    /// Bucket addressing style.
    pub addressing: S3Addressing,
    /// Signing credentials.
    pub credentials: S3Credentials,
    /// Object lock mode; `None` stores objects without retention.
    pub object_lock: Option<S3ObjectLockMode>,
    /// Permits an `http://` endpoint, for a service on a trusted network.
    /// Objects are encrypted either way, but metadata and keys are not.
    pub allow_plain_http: bool,
    /// Whole-request deadline, 1 second to 5 minutes.
    pub request_timeout: Duration,
}

impl S3EvidenceStoreConfig {
    /// Validates the endpoint, bucket, prefix and limits.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConfig`] for any unsafe or malformed value.
    pub fn new(settings: S3EvidenceStoreSettings<'_>) -> Result<Self, EvidenceError> {
        let endpoint = Url::parse(settings.endpoint).map_err(|_| EvidenceError::InvalidConfig)?;
        let scheme = match endpoint.scheme() {
            "https" => "https",
            "http" if settings.allow_plain_http => "http",
            _ => return Err(EvidenceError::InvalidConfig),
        };
        let host = endpoint.host_str().ok_or(EvidenceError::InvalidConfig)?;
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(EvidenceError::InvalidConfig);
        }
        let authority = match endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let region_valid = !settings.region.is_empty()
            && settings.region.len() <= 32
            && settings
                .region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        let bucket_valid = valid_bucket(settings.bucket)
            // A dotted bucket breaks TLS name checks under virtual-hosted style.
            && !(settings.addressing == S3Addressing::VirtualHosted
                && settings.bucket.contains('.'));
        if !region_valid
            || !bucket_valid
            || !valid_prefix(settings.prefix)
            || settings.request_timeout < Duration::from_secs(1)
            || settings.request_timeout > REQUEST_TIMEOUT_MAX
        {
            return Err(EvidenceError::InvalidConfig);
        }
        Ok(Self {
            scheme,
            authority,
            region: settings.region.to_owned(),
            bucket: settings.bucket.to_owned(),
            prefix: settings.prefix.to_owned(),
            addressing: settings.addressing,
            credentials: settings.credentials,
            object_lock: settings.object_lock,
            allow_plain_http: settings.allow_plain_http,
            request_timeout: settings.request_timeout,
        })
    }

    /// Returns the configured object lock mode.
    #[must_use]
    pub const fn object_lock(&self) -> Option<S3ObjectLockMode> {
        self.object_lock
    }
}

/// Encrypted evidence storage in an S3-compatible bucket.
///
/// The API mirrors [`crate::LocalEvidenceVault`] for the generic evidence
/// family; calibration report and lineage-review objects stay local.
pub struct S3EvidenceVault {
    client: S3Client,
    key_id: String,
    max_artifact_bytes: usize,
    max_retention: chrono::TimeDelta,
    root_key: EvidenceKey,
}

impl fmt::Debug for S3EvidenceVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3EvidenceVault")
            .field("bucket", &self.client.config().bucket)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl S3EvidenceVault {
    /// Validates the vault policy and probes the bucket.
    ///
    /// The probe reads the bucket's versioning and object lock configuration;
    /// it fails when the bucket is unreachable, the credentials are refused,
    /// or object lock is configured but the bucket was not created with it.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConfig`] for an unsafe policy or a bucket
    /// without the configured lock, and [`EvidenceError::Io`] when the bucket
    /// cannot be read.
    pub fn open(
        store: S3EvidenceStoreConfig,
        key_id: impl Into<String>,
        max_artifact_bytes: usize,
        max_retention_days: u16,
        root_key: EvidenceKey,
    ) -> Result<Self, EvidenceError> {
        let key_id = key_id.into();
        let max_retention = validate_vault_policy(&key_id, max_artifact_bytes, max_retention_days)?;
        let client = S3Client::new(store);
        let versioned = client.versioning_enabled()?;
        if client.config().object_lock.is_some() && !(versioned && client.object_lock_enabled()?) {
            return Err(EvidenceError::InvalidConfig);
        }
        Ok(Self {
            client,
            key_id,
            max_artifact_bytes,
            max_retention,
            root_key,
        })
    }

    /// Encrypts one object and publishes ciphertext, manifest and manifest
    /// HMAC, in that order, each with a create-only conditional write.
    ///
    /// A returned manifest always names a stored ciphertext. A failure after
    /// the first write leaves only an unreachable orphan.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for invalid input, crypto failure, or a
    /// refused or unreachable store.
    pub fn write(
        &self,
        command: &EvidenceWrite<'_>,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        let sealed = seal(
            &self.root_key,
            &self.key_id,
            self.max_artifact_bytes,
            self.max_retention,
            command,
        )?;
        let scope = self.scope(command.tenant_id, command.site_id);
        let artifact_id = &sealed.manifest.artifact_id;
        // The lock ends with the read deadline: before it the object may not
        // go, after it retention must be able to remove it.
        let retain_until = command.expires_at;
        self.client.put_new(
            &format!("{scope}{}", sealed.manifest.storage.locator),
            &sealed.envelope,
            retain_until,
        )?;
        self.client.put_new(
            &format!("{scope}{artifact_id}.manifest.json"),
            &sealed.manifest_bytes,
            retain_until,
        )?;
        self.client.put_new(
            &format!("{scope}{artifact_id}.manifest.hmac"),
            &sealed.manifest_auth,
            retain_until,
        )?;
        Ok(VerifiedEvidenceManifest(sealed.manifest))
    }

    /// Loads and validates one scoped manifest while leaving plaintext unread.
    ///
    /// # Errors
    /// Returns [`EvidenceError::NotAvailable`] uniformly for unknown, expired, or
    /// cross-scope IDs; malformed stored metadata returns corruption errors.
    pub fn read_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        self.read_manifest_at(tenant_id, site_id, artifact_id, Utc::now())
    }

    fn read_manifest_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedEvidenceManifest, EvidenceError> {
        let manifest = self
            .load_authenticated_manifest(tenant_id, site_id, artifact_id)?
            .ok_or(EvidenceError::NotAvailable)?;
        validate_manifest(
            &manifest,
            tenant_id,
            site_id,
            artifact_id,
            &self.key_id,
            now,
        )?;
        Ok(VerifiedEvidenceManifest(manifest))
    }

    /// Both sidecars authenticated, or `None` when either is absent.
    fn load_authenticated_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<Option<EvidenceManifest>, EvidenceError> {
        validate_artifact_id(artifact_id)?;
        let scope = self.scope(tenant_id, site_id);
        let Some(bytes) = self.client.get_bounded(
            &format!("{scope}{artifact_id}.manifest.json"),
            MANIFEST_BYTES_MAX,
        )?
        else {
            return Ok(None);
        };
        let Some(authentication) = self
            .client
            .get_bounded(&format!("{scope}{artifact_id}.manifest.hmac"), 32)?
        else {
            return Ok(None);
        };
        decode_authenticated_manifest(&self.root_key, &bytes.bytes, &authentication.bytes).map(Some)
    }

    /// Authenticates and decrypts one unexpired object in the supplied scope.
    ///
    /// Callers must separately enforce the requested metadata/content approval.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for unavailable, corrupt, oversized, or
    /// unauthentic evidence, or an unreachable store.
    pub fn read_content(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        let verified = self.read_manifest_at(tenant_id, site_id, artifact_id, Utc::now())?;
        self.decrypt(tenant_id, site_id, verified.manifest())
    }

    /// Authenticates, decrypts, and binds content to an already authorized
    /// manifest, rechecking the stored manifest before and after decryption.
    ///
    /// # Errors
    /// Returns [`EvidenceError::CorruptEvidence`] when either stored manifest
    /// observation differs from `expected`; otherwise as [`Self::read_content`].
    pub fn read_content_matching_manifest(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &VerifiedEvidenceManifest,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        let manifest = expected.manifest();
        let artifact_id = manifest.artifact_id.as_str();
        let observed = self.read_manifest_at(tenant_id, site_id, artifact_id, Utc::now())?;
        if observed.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        let plaintext = self.decrypt(tenant_id, site_id, manifest)?;
        let current = self.read_manifest_at(tenant_id, site_id, artifact_id, Utc::now())?;
        if current.manifest() != manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(plaintext)
    }

    fn decrypt(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        manifest: &EvidenceManifest,
    ) -> Result<Zeroizing<Vec<u8>>, EvidenceError> {
        let envelope = self
            .client
            .get_bounded(
                &format!(
                    "{}{}",
                    self.scope(tenant_id, site_id),
                    manifest.storage.locator
                ),
                self.max_envelope_bytes(),
            )?
            .ok_or(EvidenceError::NotAvailable)?;
        open_envelope(
            &self.root_key,
            tenant_id,
            site_id,
            &manifest.artifact_id,
            manifest,
            &envelope.bytes,
        )
    }

    /// Removes only expired ciphertext matching the exact catalog manifest.
    ///
    /// The caller durably audits deletion intent first. The version deleted is
    /// the one whose digest was just verified. Signed sidecars stay for crash
    /// retries. Under object lock the store refuses deletion until the lock
    /// ends, which surfaces as a retryable [`EvidenceError::Io`].
    ///
    /// # Errors
    /// Returns [`EvidenceError`] on unexpired, mismatched or corrupt evidence,
    /// or a refused or unreachable store.
    pub fn purge_expired(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &EvidenceManifest,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        self.purge_expired_at(tenant_id, site_id, expected, Utc::now())
    }

    fn purge_expired_at(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        expected: &EvidenceManifest,
        now: DateTime<Utc>,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        let manifest = self
            .load_authenticated_manifest(tenant_id, site_id, &expected.artifact_id)?
            .ok_or(EvidenceError::NotAvailable)?;
        let expires_at = validate_manifest_fields(
            &manifest,
            tenant_id,
            site_id,
            &expected.artifact_id,
            &self.key_id,
        )?;
        if &manifest != expected {
            return Err(EvidenceError::CorruptEvidence);
        }
        if expires_at > now {
            return Err(EvidenceError::NotAvailable);
        }
        let key = format!(
            "{}{}",
            self.scope(tenant_id, site_id),
            manifest.storage.locator
        );
        let Some(envelope) = self.client.get_bounded(&key, self.max_envelope_bytes())? else {
            return Ok(EvidencePurgeOutcome::AlreadyAbsent);
        };
        if lower_hex(&sha256(&envelope.bytes)) != manifest.integrity.digest {
            return Err(EvidenceError::CorruptEvidence);
        }
        self.client.delete(&key, envelope.version_id.as_deref())?;
        Ok(EvidencePurgeOutcome::Removed)
    }

    /// Finds the next page, after an artifact ID, of ciphertexts older than
    /// `grace` whose lock (if any) has ended. A complete, authenticated
    /// sidecar pair is accepted; a partial or malformed pair is skipped.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] for an invalid bound or cursor, or an
    /// unreachable store.
    pub fn list_orphan_candidates_after(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        grace: Duration,
        limit: u16,
        after: Option<&str>,
    ) -> Result<Vec<EvidenceOrphanCandidate>, EvidenceError> {
        if !(1..=32).contains(&limit) || grace.is_zero() || grace > Duration::from_hours(720) {
            return Err(EvidenceError::InvalidConfig);
        }
        if after.is_some_and(|cursor| validate_artifact_id(cursor).is_err()) {
            return Err(EvidenceError::InvalidConfig);
        }
        let grace = chrono::TimeDelta::from_std(grace).map_err(|_| EvidenceError::InvalidConfig)?;
        let now = Utc::now();
        let scope = self.scope(tenant_id, site_id);
        let mut start_after =
            after.map_or_else(String::new, |cursor| format!("{scope}{cursor}.xev"));
        let mut scanned = 0usize;
        let mut candidates = Vec::new();
        loop {
            let page = self.client.list(&scope, &start_after)?;
            for object in &page.objects {
                scanned += 1;
                if scanned > SCAN_KEYS_MAX {
                    return Err(EvidenceError::UnsafePath);
                }
                if candidates.len() == usize::from(limit) {
                    return Ok(candidates);
                }
                let Some(artifact_id) = object
                    .key
                    .strip_prefix(&scope)
                    .and_then(|name| name.strip_suffix(".xev"))
                else {
                    continue;
                };
                if validate_artifact_id(artifact_id).is_err()
                    || after.is_some_and(|cursor| artifact_id <= cursor)
                    || object.bytes > self.max_envelope_bytes()
                    || now.signed_duration_since(object.last_modified) < grace
                {
                    continue;
                }
                if let Some(candidate) =
                    self.orphan_candidate(tenant_id, site_id, artifact_id, object, now)?
                {
                    candidates.push(candidate);
                }
            }
            match page.objects.last() {
                Some(last) if page.truncated => start_after.clone_from(&last.key),
                _ => return Ok(candidates),
            }
        }
    }

    fn orphan_candidate(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
        object: &client::ListedObject,
        now: DateTime<Utc>,
    ) -> Result<Option<EvidenceOrphanCandidate>, EvidenceError> {
        let Some(head) = self.client.head(&object.key)? else {
            return Ok(None);
        };
        if head.retain_until.is_some_and(|until| until > now) {
            return Ok(None);
        }
        let Some(authenticated_manifest) = self.orphan_sidecars(tenant_id, site_id, artifact_id)?
        else {
            return Ok(None);
        };
        let modified_millis = u64::try_from(object.last_modified.timestamp_millis())
            .map_err(|_| EvidenceError::UnsafePath)?;
        EvidenceOrphanCandidate::from_observation(
            artifact_id,
            authenticated_manifest,
            object.bytes,
            modified_millis / 1000,
            u32::try_from(modified_millis % 1000).map_err(|_| EvidenceError::UnsafePath)?
                * 1_000_000,
        )
        .map(Some)
    }

    /// `Some(false)` for no sidecars, `Some(true)` for an authentic in-scope
    /// pair, `None` for anything else, which an orphan scan leaves alone.
    fn orphan_sidecars(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        artifact_id: &str,
    ) -> Result<Option<bool>, EvidenceError> {
        let scope = self.scope(tenant_id, site_id);
        let has_manifest = self
            .client
            .head(&format!("{scope}{artifact_id}.manifest.json"))?
            .is_some();
        let has_hmac = self
            .client
            .head(&format!("{scope}{artifact_id}.manifest.hmac"))?
            .is_some();
        match (has_manifest, has_hmac) {
            (false, false) => Ok(Some(false)),
            (true, true) => {
                let Ok(Some(manifest)) =
                    self.load_authenticated_manifest(tenant_id, site_id, artifact_id)
                else {
                    return Ok(None);
                };
                Ok(validate_manifest_fields(
                    &manifest,
                    tenant_id,
                    site_id,
                    artifact_id,
                    &self.key_id,
                )
                .is_ok()
                .then_some(true))
            }
            _ => Ok(None),
        }
    }

    /// Removes one previously observed orphan ciphertext after rechecking its
    /// size, modification second and sidecars, deleting the version checked.
    ///
    /// # Errors
    /// Returns [`EvidenceError`] when the object or its sidecars changed, or
    /// the store refuses or is unreachable. An absent object is idempotent.
    pub fn purge_orphan(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        candidate: &EvidenceOrphanCandidate,
    ) -> Result<EvidencePurgeOutcome, EvidenceError> {
        let artifact_id = candidate.artifact_id();
        let key = format!("{}{artifact_id}.xev", self.scope(tenant_id, site_id));
        let Some(head) = self.client.head(&key)? else {
            return Ok(EvidencePurgeOutcome::AlreadyAbsent);
        };
        // HEAD reports whole seconds where the listing had milliseconds.
        let observed_seconds =
            u64::try_from(head.last_modified.timestamp()).map_err(|_| EvidenceError::UnsafePath)?;
        if head.bytes != candidate.observed_bytes()
            || observed_seconds != candidate.observed_modified().0
        {
            return Err(EvidenceError::UnsafePath);
        }
        match self.orphan_sidecars(tenant_id, site_id, artifact_id)? {
            Some(authenticated) if authenticated == candidate.authenticated_manifest() => {}
            _ => return Err(EvidenceError::CorruptEvidence),
        }
        if candidate.authenticated_manifest() {
            let manifest = self
                .load_authenticated_manifest(tenant_id, site_id, artifact_id)?
                .ok_or(EvidenceError::CorruptEvidence)?;
            let envelope = self
                .client
                .get_bounded(&key, self.max_envelope_bytes())?
                .ok_or(EvidenceError::CorruptEvidence)?;
            if lower_hex(&sha256(&envelope.bytes)) != manifest.integrity.digest
                || envelope.version_id != head.version_id
            {
                return Err(EvidenceError::CorruptEvidence);
            }
        }
        self.client.delete(&key, head.version_id.as_deref())?;
        Ok(EvidencePurgeOutcome::Removed)
    }

    /// Copies one complete, not-yet-expired generic evidence object out of
    /// `local` into this bucket, unchanged: the same ciphertext, typed
    /// manifest and manifest HMAC bytes, locked (if configured) to the same
    /// `expires_at`. The catalog keeps pointing at the same artifact ID
    /// either way, since both backends store identical objects (see the
    /// module docs).
    ///
    /// Already-expired local objects are left to the local retention pass:
    /// no reader can authorize them on either backend, so there is nothing
    /// to gain from copying them before they are purged.
    ///
    /// Every write is create-only, so re-running this on an
    /// already-migrated artifact is a safe no-op: see
    /// [`EvidenceMigrationOutcome::AlreadyMigrated`]. A migration tool may
    /// always retry the whole vault after a partial failure or a restart.
    ///
    /// # Errors
    /// Returns [`EvidenceError::InvalidConfig`] when `local` and this bucket
    /// were not opened with the same key id; [`EvidenceError::NotAvailable`]
    /// for an artifact id with no local object, or one already expired;
    /// [`EvidenceError::CorruptEvidence`] when the local manifest, HMAC or
    /// ciphertext digest does not check out, or when what lands in the
    /// bucket does not read back as the same manifest. Otherwise as a
    /// failed local read or bucket request.
    pub fn migrate_from_local(
        &self,
        local: &LocalEvidenceVault,
        artifact_id: &str,
    ) -> Result<EvidenceMigrationOutcome, EvidenceError> {
        if self.key_id != local.config.key_id {
            return Err(EvidenceError::InvalidConfig);
        }
        validate_artifact_id(artifact_id)?;
        let manifest_name = format!("{artifact_id}.manifest.json");
        let hmac_name = format!("{artifact_id}.manifest.hmac");
        let manifest_bytes =
            read_private_bounded(&local.config.root.join(&manifest_name), MANIFEST_BYTES_MAX)
                .map_err(hide_absence)?;
        let manifest_auth =
            read_private_bounded(&local.config.root.join(&hmac_name), 32).map_err(hide_absence)?;
        let manifest =
            decode_authenticated_manifest(&local.root_key, &manifest_bytes, &manifest_auth)?;
        let tenant_id =
            TenantId::parse(&manifest.tenant_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let site_id =
            SiteId::parse(&manifest.site_id).map_err(|_| EvidenceError::CorruptEvidence)?;
        let expires_at = validate_manifest_fields(
            &manifest,
            &tenant_id,
            &site_id,
            artifact_id,
            &local.config.key_id,
        )?;
        if expires_at <= Utc::now() {
            return Err(EvidenceError::NotAvailable);
        }
        let envelope = read_private_bounded(
            &local.config.root.join(&manifest.storage.locator),
            self.max_envelope_bytes(),
        )
        .map_err(hide_absence)?;
        if lower_hex(&sha256(&envelope)) != manifest.integrity.digest {
            return Err(EvidenceError::CorruptEvidence);
        }
        let scope = self.scope(&tenant_id, &site_id);
        let already_present = self
            .load_authenticated_manifest(&tenant_id, &site_id, artifact_id)?
            .is_some();
        for (key, bytes) in [
            (
                format!("{scope}{}", manifest.storage.locator),
                envelope.as_slice(),
            ),
            (format!("{scope}{manifest_name}"), manifest_bytes.as_slice()),
            (format!("{scope}{hmac_name}"), manifest_auth.as_slice()),
        ] {
            match self.client.put_new(&key, bytes, expires_at) {
                Ok(()) => {}
                Err(EvidenceError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let verified = self.read_manifest_at(&tenant_id, &site_id, artifact_id, Utc::now())?;
        if verified.manifest() != &manifest {
            return Err(EvidenceError::CorruptEvidence);
        }
        Ok(if already_present {
            EvidenceMigrationOutcome::AlreadyMigrated
        } else {
            EvidenceMigrationOutcome::Migrated
        })
    }

    fn scope(&self, tenant_id: &TenantId, site_id: &SiteId) -> String {
        // Tenant and site IDs are `[A-Za-z0-9_.-]`; the `t-`/`s-` markers keep
        // a `.` or `..` ID from forming a dot segment.
        format!(
            "{}t-{}/s-{}/",
            self.client.config().prefix,
            tenant_id.as_str(),
            site_id.as_str()
        )
    }

    fn max_envelope_bytes(&self) -> u64 {
        (self.max_artifact_bytes as u64 + 1 + NONCE_BYTES as u64 + TAG_BYTES as u64)
            .min(MAX_SINGLE_ENVELOPE_BYTES)
    }
}

fn valid_bucket(bucket: &str) -> bool {
    let bytes = bucket.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && !bucket.contains("..")
}

fn valid_prefix(prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let Some(body) = prefix.strip_suffix('/') else {
        return false;
    };
    prefix.len() <= PREFIX_BYTES_MAX
        && body.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
}
