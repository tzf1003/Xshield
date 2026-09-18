use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use xshield_core::domain::{EventId, RequestId, SiteId, TenantId};
use xshield_evidence::{
    EvidenceClassification, EvidenceFidelity, EvidenceIntegrity, EvidenceManifest, EvidenceStorage,
    VerifiedEvidenceManifest,
};

const REQUEST_ARTIFACTS_MAX: u16 = 128;
const CATALOG_EVENT_TYPE: &str = "evidence.cataloged";
const CATALOG_PUBLISHED_REASON: &str = "EVIDENCE_CATALOG_PUBLISHED";

/// One authenticated manifest ready for catalog publication and audit.
pub struct EvidenceCatalogPublish<'a> {
    manifest: &'a VerifiedEvidenceManifest,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> EvidenceCatalogPublish<'a> {
    /// Binds the structured audit envelope to the manifest, event identity,
    /// and terminal publication outcome.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the audit envelope does not
    /// describe this exact publication.
    pub fn new(
        manifest: &'a VerifiedEvidenceManifest,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if !catalog_event_matches(manifest.manifest(), event_id, event_envelope) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            manifest,
            event_id,
            event_envelope,
        })
    }
}

/// Bounded exact-scope lookup for artifacts produced by one request.
pub struct EvidenceCatalogQuery<'a> {
    tenant_id: &'a TenantId,
    site_id: &'a SiteId,
    request_id: &'a RequestId,
    limit: u16,
}

impl<'a> EvidenceCatalogQuery<'a> {
    /// Creates a query returning at most 128 active, unexpired manifests.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for a zero or oversized limit.
    pub fn new(
        tenant_id: &'a TenantId,
        site_id: &'a SiteId,
        request_id: &'a RequestId,
        limit: u16,
    ) -> Result<Self, StoreError> {
        if !(1..=REQUEST_ARTIFACTS_MAX).contains(&limit) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant_id,
            site_id,
            request_id,
            limit,
        })
    }
}

/// Durable catalog publication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceCatalogWriteOutcome {
    /// Manifest and audit event were inserted atomically.
    Published,
    /// The exact manifest and audit event were already committed.
    Existing,
    /// The artifact identity is already bound to different durable data.
    Conflict,
}

impl EvidenceCatalogWriteOutcome {
    /// Returns the stable terminal reason code for structured audit callers.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Published => CATALOG_PUBLISHED_REASON,
            Self::Existing => "EVIDENCE_CATALOG_ALREADY_PUBLISHED",
            Self::Conflict => "EVIDENCE_CATALOG_CONFLICT",
        }
    }
}

/// Active catalog metadata for one encrypted evidence object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogArtifact {
    manifest: EvidenceManifest,
    recorded_at: DateTime<Utc>,
}

impl CatalogArtifact {
    /// Returns the typed catalog manifest. Content access still requires the
    /// evidence vault to authenticate its own manifest and ciphertext.
    #[must_use]
    pub const fn manifest(&self) -> &EvidenceManifest {
        &self.manifest
    }

    /// Returns when the manifest was durably cataloged.
    #[must_use]
    pub const fn recorded_at(&self) -> DateTime<Utc> {
        self.recorded_at
    }
}

impl PostgresIdentityStore {
    /// Atomically publishes one authenticated manifest and its audit event.
    ///
    /// Exact retries are idempotent. Reusing an artifact identity for different
    /// metadata or a different event fails with [`EvidenceCatalogWriteOutcome::Conflict`].
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid timestamps, corrupt existing state,
    /// or database failure. No catalog row survives an audit insert failure.
    pub async fn publish_evidence_manifest(
        &self,
        command: EvidenceCatalogPublish<'_>,
    ) -> Result<EvidenceCatalogWriteOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let recorded_at = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        command
            .manifest
            .manifest()
            .validate_catalog_shape(recorded_at)
            .map_err(|_| StoreError::InvalidCommand)?;
        if insert_catalog_row(&mut transaction, &command, recorded_at).await? {
            insert_catalog_event(&mut transaction, &command).await?;
            transaction.commit().await?;
            return Ok(EvidenceCatalogWriteOutcome::Published);
        }
        let outcome = existing_catalog_outcome(&mut transaction, &command).await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Lists active, unexpired catalog manifests for one exact request scope.
    ///
    /// `PostgreSQL` supplies the current time; callers cannot choose the expiry
    /// reference. Results are ordered by publication time and artifact identity.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt durable metadata.
    pub async fn list_request_artifacts(
        &self,
        query: EvidenceCatalogQuery<'_>,
    ) -> Result<Vec<CatalogArtifact>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM xshield.artifact_catalog
             WHERE tenant_id = $1 AND site_id = $2 AND request_id = $3
               AND status = 'active' AND deleted_at IS NULL
               AND expires_at > clock_timestamp()
             ORDER BY recorded_at, artifact_id
             LIMIT $4",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(query.request_id.as_str())
        .bind(i64::from(query.limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(catalog_artifact).collect()
    }
}

async fn insert_catalog_row(
    transaction: &mut Transaction<'_, Postgres>,
    command: &EvidenceCatalogPublish<'_>,
    recorded_at: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let manifest = command.manifest.manifest();
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| StoreError::InvalidCommand)?
        .with_timezone(&Utc);
    let bytes_observed = i64::try_from(manifest.bytes_observed)
        .map_err(|_| StoreError::NumericRange("bytes_observed"))?;
    let bytes_saved =
        i64::try_from(manifest.bytes_saved).map_err(|_| StoreError::NumericRange("bytes_saved"))?;
    let key_ref = manifest
        .storage
        .key_ref
        .as_deref()
        .ok_or(StoreError::InvalidCommand)?;
    let inserted = sqlx::query(
        "INSERT INTO xshield.artifact_catalog (
            tenant_id, site_id, artifact_id, request_id, schema_version,
            kind, content_type, capture_status, fidelity, bytes_observed,
            bytes_saved, classification, example_only, storage_profile,
            storage_locator, key_ref, integrity_algorithm, integrity_digest,
            parent_refs, recorded_at, expires_at, catalog_event_id,
            status, deleted_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
            'active', NULL
         ) ON CONFLICT (tenant_id, site_id, artifact_id) DO NOTHING",
    )
    .bind(&manifest.tenant_id)
    .bind(&manifest.site_id)
    .bind(&manifest.artifact_id)
    .bind(&manifest.request_id)
    .bind(i16::from(manifest.schema_version))
    .bind(&manifest.kind)
    .bind(&manifest.content_type)
    .bind(&manifest.capture_status)
    .bind(fidelity_name(manifest.fidelity))
    .bind(bytes_observed)
    .bind(bytes_saved)
    .bind(classification_name(manifest.classification))
    .bind(manifest.example_only)
    .bind(&manifest.storage.profile)
    .bind(&manifest.storage.locator)
    .bind(key_ref)
    .bind(&manifest.integrity.algorithm)
    .bind(&manifest.integrity.digest)
    .bind(&manifest.parent_refs)
    .bind(recorded_at)
    .bind(expires_at)
    .bind(command.event_id.as_str())
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    Ok(inserted == 1)
}

async fn existing_catalog_outcome(
    transaction: &mut Transaction<'_, Postgres>,
    command: &EvidenceCatalogPublish<'_>,
) -> Result<EvidenceCatalogWriteOutcome, StoreError> {
    let manifest = command.manifest.manifest();
    let row = sqlx::query(
        "SELECT catalog.*,
                outbox.event_id AS outbox_event_id,
                outbox.tenant_id AS outbox_tenant_id,
                outbox.site_id AS outbox_site_id,
                outbox.aggregate_ref AS outbox_aggregate_ref,
                outbox.event_type AS outbox_event_type,
                outbox.envelope AS outbox_envelope
         FROM xshield.artifact_catalog catalog
         LEFT JOIN xshield.audit_outbox outbox
           ON outbox.event_id = catalog.catalog_event_id
         WHERE catalog.tenant_id = $1 AND catalog.site_id = $2
           AND catalog.artifact_id = $3",
    )
    .bind(&manifest.tenant_id)
    .bind(&manifest.site_id)
    .bind(&manifest.artifact_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(StoreError::CorruptData("artifact_catalog_conflict"))?;
    let entry = catalog_artifact(&row)?;
    if row.try_get::<Option<&str>, _>("outbox_event_id")?.is_none() {
        return Err(StoreError::CorruptData("artifact_catalog_outbox"));
    }
    let exact_event = row.try_get::<&str, _>("catalog_event_id")? == command.event_id.as_str()
        && row.try_get::<Option<&str>, _>("outbox_event_id")? == Some(command.event_id.as_str())
        && row.try_get::<Option<&str>, _>("outbox_tenant_id")? == Some(manifest.tenant_id.as_str())
        && row.try_get::<Option<&str>, _>("outbox_site_id")? == Some(manifest.site_id.as_str())
        && row.try_get::<Option<&str>, _>("outbox_aggregate_ref")?
            == Some(manifest.artifact_id.as_str())
        && row.try_get::<Option<&str>, _>("outbox_event_type")? == Some(CATALOG_EVENT_TYPE)
        && row.try_get::<Option<Value>, _>("outbox_envelope")?.as_ref()
            == Some(command.event_envelope);
    Ok(if entry.manifest == *manifest && exact_event {
        EvidenceCatalogWriteOutcome::Existing
    } else {
        EvidenceCatalogWriteOutcome::Conflict
    })
}

async fn insert_catalog_event(
    transaction: &mut Transaction<'_, Postgres>,
    command: &EvidenceCatalogPublish<'_>,
) -> Result<(), StoreError> {
    let manifest = command.manifest.manifest();
    sqlx::query(
        "INSERT INTO xshield.audit_outbox (
            event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
         ) VALUES ($1, $2, $3, $4, 'evidence.cataloged', $5)",
    )
    .bind(command.event_id.as_str())
    .bind(&manifest.tenant_id)
    .bind(&manifest.site_id)
    .bind(&manifest.artifact_id)
    .bind(command.event_envelope)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn catalog_event_matches(
    manifest: &EvidenceManifest,
    event_id: &EventId,
    envelope: &Value,
) -> bool {
    let Some(payload) = envelope.get("payload").and_then(Value::as_object) else {
        return false;
    };
    envelope.get("schema_version").and_then(Value::as_u64) == Some(3)
        && envelope.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
        && envelope.get("event_type").and_then(Value::as_str) == Some(CATALOG_EVENT_TYPE)
        && envelope.get("tenant_id").and_then(Value::as_str) == Some(&manifest.tenant_id)
        && envelope.get("site_id").and_then(Value::as_str) == Some(&manifest.site_id)
        && envelope.get("request_id").and_then(Value::as_str) == Some(&manifest.request_id)
        && envelope
            .get("evidence_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.len() == 1 && refs[0].as_str() == Some(manifest.artifact_id.as_str())
            })
        && payload.get("stage").and_then(Value::as_str) == Some("evidence_catalog")
        && payload.get("outcome").and_then(Value::as_str) == Some("PASS")
        && payload.get("reason_code").and_then(Value::as_str) == Some(CATALOG_PUBLISHED_REASON)
        && payload.get("artifact_id").and_then(Value::as_str) == Some(manifest.artifact_id.as_str())
}

fn catalog_artifact(row: &PgRow) -> Result<CatalogArtifact, StoreError> {
    let recorded_at = row.try_get::<DateTime<Utc>, _>("recorded_at")?;
    let expires_at = row.try_get::<DateTime<Utc>, _>("expires_at")?;
    let schema_version = u8::try_from(row.try_get::<i16, _>("schema_version")?)
        .map_err(|_| StoreError::CorruptData("artifact_schema_version"))?;
    let bytes_observed = u64::try_from(row.try_get::<i64, _>("bytes_observed")?)
        .map_err(|_| StoreError::CorruptData("artifact_bytes_observed"))?;
    let bytes_saved = u64::try_from(row.try_get::<i64, _>("bytes_saved")?)
        .map_err(|_| StoreError::CorruptData("artifact_bytes_saved"))?;
    let fidelity = match row.try_get::<&str, _>("fidelity")? {
        "entity_exact" => EvidenceFidelity::EntityExact,
        "semantic" => EvidenceFidelity::Semantic,
        "redacted" => EvidenceFidelity::Redacted,
        _ => return Err(StoreError::CorruptData("artifact_fidelity")),
    };
    let classification = match row.try_get::<&str, _>("classification")? {
        "INTERNAL" => EvidenceClassification::Internal,
        "SENSITIVE" => EvidenceClassification::Sensitive,
        "RESTRICTED" => EvidenceClassification::Restricted,
        _ => return Err(StoreError::CorruptData("artifact_classification")),
    };
    let manifest = EvidenceManifest {
        schema_version,
        artifact_id: row.try_get("artifact_id")?,
        request_id: row.try_get("request_id")?,
        tenant_id: row.try_get("tenant_id")?,
        site_id: row.try_get("site_id")?,
        kind: row.try_get("kind")?,
        content_type: row.try_get("content_type")?,
        capture_status: row.try_get("capture_status")?,
        fidelity,
        bytes_observed,
        bytes_saved,
        classification,
        example_only: row.try_get("example_only")?,
        storage: EvidenceStorage {
            profile: row.try_get("storage_profile")?,
            locator: row.try_get("storage_locator")?,
            key_ref: Some(row.try_get("key_ref")?),
        },
        integrity: EvidenceIntegrity {
            algorithm: row.try_get("integrity_algorithm")?,
            digest: row.try_get("integrity_digest")?,
        },
        parent_refs: row.try_get("parent_refs")?,
        expires_at: expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    manifest
        .validate_catalog_shape(recorded_at)
        .map_err(|_| StoreError::CorruptData("artifact_manifest"))?;
    Ok(CatalogArtifact {
        manifest,
        recorded_at,
    })
}

const fn fidelity_name(value: EvidenceFidelity) -> &'static str {
    match value {
        EvidenceFidelity::EntityExact => "entity_exact",
        EvidenceFidelity::Semantic => "semantic",
        EvidenceFidelity::Redacted => "redacted",
    }
}

const fn classification_name(value: EvidenceClassification) -> &'static str {
    match value {
        EvidenceClassification::Internal => "INTERNAL",
        EvidenceClassification::Sensitive => "SENSITIVE",
        EvidenceClassification::Restricted => "RESTRICTED",
    }
}

#[cfg(test)]
mod tests {
    use super::{EvidenceCatalogQuery, REQUEST_ARTIFACTS_MAX};
    use crate::StoreError;
    use xshield_core::domain::{RequestId, SiteId, TenantId};

    #[test]
    fn request_catalog_limit_is_bounded() {
        let tenant = TenantId::parse("tenant_catalog").unwrap();
        let site = SiteId::parse("site_catalog").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000901").unwrap();
        assert!(EvidenceCatalogQuery::new(&tenant, &site, &request, 1).is_ok());
        assert!(matches!(
            EvidenceCatalogQuery::new(&tenant, &site, &request, 0),
            Err(StoreError::InvalidCommand)
        ));
        assert!(matches!(
            EvidenceCatalogQuery::new(&tenant, &site, &request, REQUEST_ARTIFACTS_MAX + 1),
            Err(StoreError::InvalidCommand)
        ));
    }
}
