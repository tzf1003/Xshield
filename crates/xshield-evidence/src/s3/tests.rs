use super::*;
use crate::{EvidenceClassification, EvidenceFidelity};
use std::{env, thread};
use uuid::Uuid;
use xshield_core::domain::RequestId;

const KEY_HEX: &str = "0001020304050607080910111213141516171819202122232425262728293031";

fn credentials() -> S3Credentials {
    S3Credentials::new("access", Zeroizing::new("secret".to_owned()), None).unwrap()
}

fn settings(endpoint: &str) -> S3EvidenceStoreSettings<'_> {
    S3EvidenceStoreSettings {
        endpoint,
        region: "us-east-1",
        bucket: "evidence",
        prefix: "",
        addressing: S3Addressing::Path,
        credentials: credentials(),
        object_lock: None,
        allow_plain_http: false,
        request_timeout: Duration::from_secs(10),
    }
}

#[test]
fn config_rejects_unsafe_endpoints_and_names() {
    assert!(S3EvidenceStoreConfig::new(settings("https://s3.example.test")).is_ok());
    assert!(S3EvidenceStoreConfig::new(settings("https://s3.example.test:9000/")).is_ok());
    for endpoint in [
        "http://s3.example.test",
        "https://user:pass@s3.example.test",
        "https://s3.example.test/path",
        "https://s3.example.test?x=1",
        "ftp://s3.example.test",
        "not a url",
    ] {
        assert!(
            S3EvidenceStoreConfig::new(settings(endpoint)).is_err(),
            "{endpoint}"
        );
    }
    let plain = S3EvidenceStoreSettings {
        allow_plain_http: true,
        ..settings("http://minio:9000")
    };
    assert!(S3EvidenceStoreConfig::new(plain).is_ok());
    for bucket in ["ab", "Evidence", "-evidence", "evidence-", "a..b", "a_b"] {
        let settings = S3EvidenceStoreSettings {
            bucket,
            ..settings("https://s3.example.test")
        };
        assert!(S3EvidenceStoreConfig::new(settings).is_err(), "{bucket}");
    }
    let dotted_virtual = S3EvidenceStoreSettings {
        bucket: "evidence.example",
        addressing: S3Addressing::VirtualHosted,
        ..settings("https://s3.example.test")
    };
    assert!(S3EvidenceStoreConfig::new(dotted_virtual).is_err());
    for prefix in ["xshield/", "a/b-c.d/"] {
        let settings = S3EvidenceStoreSettings {
            prefix,
            ..settings("https://s3.example.test")
        };
        assert!(S3EvidenceStoreConfig::new(settings).is_ok(), "{prefix}");
    }
    for prefix in ["xshield", "/xshield/", "a//", "../", "a/./", "a b/"] {
        let settings = S3EvidenceStoreSettings {
            prefix,
            ..settings("https://s3.example.test")
        };
        assert!(S3EvidenceStoreConfig::new(settings).is_err(), "{prefix}");
    }
    for timeout in [Duration::ZERO, Duration::from_mins(6)] {
        let settings = S3EvidenceStoreSettings {
            request_timeout: timeout,
            ..settings("https://s3.example.test")
        };
        assert!(S3EvidenceStoreConfig::new(settings).is_err());
    }
    assert!(S3Credentials::new("", Zeroizing::new("secret".to_owned()), None).is_err());
    assert!(S3Credentials::new("a b", Zeroizing::new("secret".to_owned()), None).is_err());
    assert!(
        !format!("{:?}", credentials()).contains("secret"),
        "credentials must not format their secret"
    );
}

// The tests below need an S3-compatible service; CI runs them against MinIO:
//   XSHIELD_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
//   XSHIELD_TEST_S3_ACCESS_KEY_ID=... XSHIELD_TEST_S3_SECRET_ACCESS_KEY=... \
//   cargo test -p xshield-evidence --lib s3_minio -- --ignored
// Each test creates its own bucket.

struct Minio {
    endpoint: String,
    access_key_id: String,
    secret_access_key: String,
}

impl Minio {
    fn from_env() -> Self {
        Self {
            endpoint: env::var("XSHIELD_TEST_S3_ENDPOINT").expect("XSHIELD_TEST_S3_ENDPOINT"),
            access_key_id: env::var("XSHIELD_TEST_S3_ACCESS_KEY_ID")
                .expect("XSHIELD_TEST_S3_ACCESS_KEY_ID"),
            secret_access_key: env::var("XSHIELD_TEST_S3_SECRET_ACCESS_KEY")
                .expect("XSHIELD_TEST_S3_SECRET_ACCESS_KEY"),
        }
    }

    fn config(&self, bucket: &str, object_lock: Option<S3ObjectLockMode>) -> S3EvidenceStoreConfig {
        S3EvidenceStoreConfig::new(S3EvidenceStoreSettings {
            endpoint: &self.endpoint,
            region: "us-east-1",
            bucket,
            prefix: "xshield/evidence/",
            addressing: S3Addressing::Path,
            credentials: S3Credentials::new(
                self.access_key_id.clone(),
                Zeroizing::new(self.secret_access_key.clone()),
                None,
            )
            .unwrap(),
            object_lock,
            allow_plain_http: true,
            request_timeout: Duration::from_secs(10),
        })
        .unwrap()
    }

    /// Creates a fresh bucket and returns its name.
    fn bucket(&self, object_lock: bool) -> String {
        let name = format!("xshield-test-{}", Uuid::now_v7().simple());
        S3Client::new(self.config(&name, None))
            .create_bucket(object_lock)
            .unwrap();
        name
    }

    fn vault(&self, bucket: &str, object_lock: Option<S3ObjectLockMode>) -> S3EvidenceVault {
        S3EvidenceVault::open(
            self.config(bucket, object_lock),
            "evidence-test",
            1024 * 1024,
            1,
            EvidenceKey::from_hex(KEY_HEX).unwrap(),
        )
        .unwrap()
    }

    fn client(&self, bucket: &str) -> S3Client {
        S3Client::new(self.config(bucket, None))
    }
}

struct Scope {
    tenant: TenantId,
    site: SiteId,
    request: RequestId,
}

fn scope() -> Scope {
    Scope {
        tenant: TenantId::parse("tenant-a").unwrap(),
        site: SiteId::parse("site-a").unwrap(),
        request: RequestId::parse(format!("req_{}", Uuid::now_v7())).unwrap(),
    }
}

fn write(
    vault: &S3EvidenceVault,
    scope: &Scope,
    plaintext: &[u8],
    expires_at: DateTime<Utc>,
) -> VerifiedEvidenceManifest {
    vault
        .write(&EvidenceWrite {
            tenant_id: &scope.tenant,
            site_id: &scope.site,
            request_id: &scope.request,
            kind: "http.request.body.v1",
            content_type: "application/json",
            fidelity: EvidenceFidelity::EntityExact,
            classification: EvidenceClassification::Sensitive,
            parent_refs: &[],
            expires_at,
            plaintext,
        })
        .unwrap()
}

fn object_key(scope: &Scope, name: &str) -> String {
    format!(
        "xshield/evidence/t-{}/s-{}/{name}",
        scope.tenant.as_str(),
        scope.site.as_str()
    )
}

#[test]
#[ignore = "needs an S3-compatible service (XSHIELD_TEST_S3_ENDPOINT)"]
fn s3_minio_locked_round_trip_refuses_early_delete_and_purges_after_expiry() {
    let minio = Minio::from_env();
    let bucket = minio.bucket(true);
    let vault = minio.vault(&bucket, Some(S3ObjectLockMode::Governance));
    let scope = scope();
    let expires_at = Utc::now() + chrono::TimeDelta::seconds(4);
    let written = write(&vault, &scope, b"{\"card\":\"4111\"}", expires_at);
    let manifest = written.manifest();
    let artifact_id = manifest.artifact_id.as_str();

    let read = vault
        .read_manifest(&scope.tenant, &scope.site, artifact_id)
        .unwrap();
    assert_eq!(read.manifest(), manifest);
    assert_eq!(
        vault
            .read_content(&scope.tenant, &scope.site, artifact_id)
            .unwrap()
            .as_slice(),
        b"{\"card\":\"4111\"}"
    );
    assert_eq!(
        vault
            .read_content_matching_manifest(&scope.tenant, &scope.site, &written)
            .unwrap()
            .as_slice(),
        b"{\"card\":\"4111\"}"
    );
    let other_site = SiteId::parse("site-b").unwrap();
    assert!(matches!(
        vault.read_content(&scope.tenant, &other_site, artifact_id),
        Err(EvidenceError::NotAvailable)
    ));

    // The bucket, not only this code, refuses to drop locked evidence early:
    // a direct version delete with the same credentials is rejected.
    let client = minio.client(&bucket);
    let key = object_key(&scope, &manifest.storage.locator);
    let head = client.head(&key).unwrap().unwrap();
    assert!(head.retain_until.is_some_and(|until| until > Utc::now()));
    assert!(client.delete(&key, head.version_id.as_deref()).is_err());
    assert!(matches!(
        vault.purge_expired(&scope.tenant, &scope.site, manifest),
        Err(EvidenceError::NotAvailable)
    ));
    // Nor can a writer replace it: every write is create-only.
    assert!(matches!(
        client.put_new(&key, b"replacement", expires_at),
        Err(EvidenceError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));

    thread::sleep(Duration::from_secs(5));
    assert!(matches!(
        vault.read_content(&scope.tenant, &scope.site, artifact_id),
        Err(EvidenceError::NotAvailable)
    ));
    assert_eq!(
        vault
            .purge_expired(&scope.tenant, &scope.site, manifest)
            .unwrap(),
        EvidencePurgeOutcome::Removed
    );
    // The verified version is gone, not hidden behind a delete marker.
    assert!(client.head(&key).unwrap().is_none());
    let version = head.version_id.as_deref().unwrap();
    assert!(!client.version_exists(&key, version).unwrap());
    assert_eq!(
        vault
            .purge_expired(&scope.tenant, &scope.site, manifest)
            .unwrap(),
        EvidencePurgeOutcome::AlreadyAbsent
    );
}

#[test]
#[ignore = "needs an S3-compatible service (XSHIELD_TEST_S3_ENDPOINT)"]
fn s3_minio_open_fails_closed_without_bucket_lock() {
    let minio = Minio::from_env();
    let bucket = minio.bucket(false);
    assert!(matches!(
        S3EvidenceVault::open(
            minio.config(&bucket, Some(S3ObjectLockMode::Compliance)),
            "evidence-test",
            1024,
            1,
            EvidenceKey::from_hex(KEY_HEX).unwrap(),
        ),
        Err(EvidenceError::InvalidConfig)
    ));
    assert!(
        S3EvidenceVault::open(
            minio.config("xshield-test-missing-bucket", None),
            "evidence-test",
            1024,
            1,
            EvidenceKey::from_hex(KEY_HEX).unwrap(),
        )
        .is_err()
    );
    let wrong_secret = S3EvidenceStoreConfig::new(S3EvidenceStoreSettings {
        endpoint: &minio.endpoint,
        region: "us-east-1",
        bucket: &bucket,
        prefix: "",
        addressing: S3Addressing::Path,
        credentials: S3Credentials::new(
            minio.access_key_id.clone(),
            Zeroizing::new("not-the-secret".to_owned()),
            None,
        )
        .unwrap(),
        object_lock: None,
        allow_plain_http: true,
        request_timeout: Duration::from_secs(10),
    })
    .unwrap();
    assert!(matches!(
        S3EvidenceVault::open(
            wrong_secret,
            "evidence-test",
            1024,
            1,
            EvidenceKey::from_hex(KEY_HEX).unwrap()
        ),
        Err(EvidenceError::Io(_))
    ));
}

#[test]
#[ignore = "needs an S3-compatible service (XSHIELD_TEST_S3_ENDPOINT)"]
fn s3_minio_rejects_tampered_ciphertext_and_manifest() {
    let minio = Minio::from_env();
    let bucket = minio.bucket(false);
    let vault = minio.vault(&bucket, None);
    let client = minio.client(&bucket);
    let scope = scope();
    let expires_at = Utc::now() + chrono::TimeDelta::hours(1);

    let first = write(&vault, &scope, b"first", expires_at);
    let first_id = first.manifest().artifact_id.clone();
    let mut envelope = client
        .get_bounded(&object_key(&scope, &first.manifest().storage.locator), 1024)
        .unwrap()
        .unwrap()
        .bytes;
    let last = envelope.len() - 1;
    envelope[last] ^= 1;
    client
        .overwrite(
            &object_key(&scope, &first.manifest().storage.locator),
            &envelope,
        )
        .unwrap();
    assert!(matches!(
        vault.read_content(&scope.tenant, &scope.site, &first_id),
        Err(EvidenceError::CorruptEvidence)
    ));

    let second = write(&vault, &scope, b"second", expires_at);
    let second_id = second.manifest().artifact_id.clone();
    let mut manifest = second.manifest().clone();
    manifest.expires_at = (Utc::now() + chrono::TimeDelta::days(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    client
        .overwrite(
            &object_key(&scope, &format!("{second_id}.manifest.json")),
            &serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        vault.read_manifest(&scope.tenant, &scope.site, &second_id),
        Err(EvidenceError::CorruptEvidence)
    ));
    assert!(matches!(
        vault.read_manifest(&scope.tenant, &scope.site, "not-an-artifact"),
        Err(EvidenceError::NotAvailable)
    ));
}

#[test]
#[ignore = "needs an S3-compatible service (XSHIELD_TEST_S3_ENDPOINT)"]
#[allow(clippy::too_many_lines)]
fn s3_minio_lists_and_purges_orphans_but_skips_locked_ones() {
    let minio = Minio::from_env();
    let bucket = minio.bucket(false);
    let vault = minio.vault(&bucket, None);
    let client = minio.client(&bucket);
    let scope = scope();
    let expires_at = Utc::now() + chrono::TimeDelta::hours(1);

    // A ciphertext whose writer died before the sidecars.
    let bare = format!("artifact_{}", Uuid::now_v7());
    client
        .put_new(
            &object_key(&scope, &format!("{bare}.xev")),
            b"orphan",
            expires_at,
        )
        .unwrap();
    // A complete object the catalog never recorded.
    let complete = write(&vault, &scope, b"complete", expires_at);
    // A ciphertext with only one sidecar is left alone.
    let partial = format!("artifact_{}", Uuid::now_v7());
    client
        .put_new(
            &object_key(&scope, &format!("{partial}.xev")),
            b"partial",
            expires_at,
        )
        .unwrap();
    client
        .put_new(
            &object_key(&scope, &format!("{partial}.manifest.json")),
            b"{}",
            expires_at,
        )
        .unwrap();

    assert!(
        vault
            .list_orphan_candidates_after(
                &scope.tenant,
                &scope.site,
                Duration::from_hours(1),
                32,
                None
            )
            .unwrap()
            .is_empty(),
        "young objects are inside the grace"
    );
    thread::sleep(Duration::from_millis(2100));
    let candidates = vault
        .list_orphan_candidates_after(&scope.tenant, &scope.site, Duration::from_secs(2), 32, None)
        .unwrap();
    let mut seen = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.artifact_id().to_owned(),
                candidate.authenticated_manifest(),
            )
        })
        .collect::<Vec<_>>();
    seen.sort();
    let mut expected = vec![
        (bare.clone(), false),
        (complete.manifest().artifact_id.clone(), true),
    ];
    expected.sort();
    assert_eq!(seen, expected);
    let other_tenant = TenantId::parse("tenant-b").unwrap();
    assert!(
        vault
            .list_orphan_candidates_after(
                &other_tenant,
                &scope.site,
                Duration::from_secs(2),
                32,
                None
            )
            .unwrap()
            .is_empty()
    );
    let page = vault
        .list_orphan_candidates_after(&scope.tenant, &scope.site, Duration::from_secs(2), 1, None)
        .unwrap();
    assert_eq!(page.len(), 1);
    let rest = vault
        .list_orphan_candidates_after(
            &scope.tenant,
            &scope.site,
            Duration::from_secs(2),
            32,
            Some(page[0].artifact_id()),
        )
        .unwrap();
    assert_eq!(rest.len(), 1);
    assert_ne!(rest[0].artifact_id(), page[0].artifact_id());

    // A changed observation is refused.
    let bare_candidate = candidates
        .iter()
        .find(|candidate| candidate.artifact_id() == bare)
        .unwrap();
    let stale = EvidenceOrphanCandidate::from_observation(
        bare.clone(),
        false,
        bare_candidate.observed_bytes() + 1,
        bare_candidate.observed_modified().0,
        0,
    )
    .unwrap();
    assert!(
        vault
            .purge_orphan(&scope.tenant, &scope.site, &stale)
            .is_err()
    );

    for candidate in &candidates {
        assert_eq!(
            vault
                .purge_orphan(&scope.tenant, &scope.site, candidate)
                .unwrap(),
            EvidencePurgeOutcome::Removed
        );
        assert_eq!(
            vault
                .purge_orphan(&scope.tenant, &scope.site, candidate)
                .unwrap(),
            EvidencePurgeOutcome::AlreadyAbsent
        );
    }
    assert!(
        client
            .head(&object_key(&scope, &format!("{partial}.xev")))
            .unwrap()
            .is_some()
    );

    // Under object lock an orphan is not offered until its lock ends.
    let locked_bucket = minio.bucket(true);
    let locked = minio.vault(&locked_bucket, Some(S3ObjectLockMode::Governance));
    write(&locked, &scope, b"locked", expires_at);
    thread::sleep(Duration::from_millis(2100));
    assert!(
        locked
            .list_orphan_candidates_after(
                &scope.tenant,
                &scope.site,
                Duration::from_secs(2),
                32,
                None
            )
            .unwrap()
            .is_empty()
    );
}
