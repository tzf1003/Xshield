//! Durable, scope-bound model-evaluation cache metadata.
//!
//! This adapter stores only an opaque cache key and references to already
//! cataloged evidence. It never authenticates or reads evidence content; the
//! worker must revalidate every referenced catalog row and vault manifest
//! before treating an entry as a hit.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Timelike, Utc};
use sqlx::{Row, Transaction};
use xshield_core::domain::{ArtifactId, ModelCallId, RequestId, SiteId, TenantId};

const MODEL_CACHE_KEY_BYTES: usize = 32;

/// One exact cache record ready for a durable insert.
pub struct ModelEvaluationCacheWrite<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    cache_key: &'a [u8; MODEL_CACHE_KEY_BYTES],
    source_request: &'a RequestId,
    source_model_call: &'a ModelCallId,
    internal_artifact: &'a ArtifactId,
    input_artifact: &'a ArtifactId,
    output_artifact: &'a ArtifactId,
    call_artifact: &'a ArtifactId,
    provider: &'a str,
    provider_model_id: &'a str,
    model_revision: &'a str,
    prompt_revision: &'a str,
    resolved_model_revision: Option<&'a str>,
    expires_at: DateTime<Utc>,
}

impl<'a> ModelEvaluationCacheWrite<'a> {
    /// Binds one successful, exact-revision evaluation to its source evidence.
    ///
    /// The expiry is checked against the database clock again by the insert;
    /// the worker cannot extend evidence retention through a cache write.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid timestamp or
    /// provider/model identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        cache_key: &'a [u8; MODEL_CACHE_KEY_BYTES],
        source_request: &'a RequestId,
        source_model_call: &'a ModelCallId,
        internal_artifact: &'a ArtifactId,
        input_artifact: &'a ArtifactId,
        output_artifact: &'a ArtifactId,
        call_artifact: &'a ArtifactId,
        provider: &'a str,
        provider_model_id: &'a str,
        model_revision: &'a str,
        prompt_revision: &'a str,
        resolved_model_revision: Option<&'a str>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, StoreError> {
        if expires_at
            .timestamp_nanos_opt()
            .is_none_or(|_| date_millis(expires_at) != expires_at)
            || !matches!(
                (provider, provider_model_id),
                ("typesafe", "jev-1.13.0") | ("vercel_ai_gateway", "typesafe-ai/jev")
            )
            || !valid_name(model_revision)
            || !valid_name(prompt_revision)
            || resolved_model_revision.is_some_and(|value| !valid_name(value))
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            cache_key,
            source_request,
            source_model_call,
            internal_artifact,
            input_artifact,
            output_artifact,
            call_artifact,
            provider,
            provider_model_id,
            model_revision,
            prompt_revision,
            resolved_model_revision,
            expires_at,
        })
    }
}

/// Revalidated-independent metadata needed by the worker to inspect a hit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelEvaluationCacheEntry {
    /// Request that originally produced the source evidence.
    pub source_request: RequestId,
    /// Original model call referenced by the cache hit audit event.
    pub source_model_call: ModelCallId,
    /// Typed internal-input evidence reference.
    pub internal_artifact: ArtifactId,
    /// Typed provider-input evidence reference.
    pub input_artifact: ArtifactId,
    /// Typed provider-output evidence reference.
    pub output_artifact: ArtifactId,
    /// Typed model-call record evidence reference.
    pub call_artifact: ArtifactId,
    /// Provider identity frozen when the source was stored.
    pub provider: String,
    /// Wire model identity frozen when the source was stored.
    pub provider_model_id: String,
    /// Internal model revision.
    pub model_revision: String,
    /// Prompt revision.
    pub prompt_revision: String,
    /// Exact resolved revision, when the provider proved one.
    pub resolved_model_revision: Option<String>,
}

/// Result of an attempted cache insert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelEvaluationCacheWriteOutcome {
    /// A new key/source binding was committed.
    Stored,
    /// The exact key/source binding already existed.
    Existing,
    /// The key or source call was already bound to different facts.
    Conflict,
}

impl PostgresIdentityStore {
    /// Looks up one unexpired cache record in the exact tenant/site scope.
    ///
    /// Source catalog rows are joined and must still be active and unexpired;
    /// the worker nevertheless rechecks each row and vault sidecar before use.
    /// Missing, expired, deleted, or differently scoped sources return `None`.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the database is unavailable or a durable
    /// cache row violates the typed identity contract.
    pub async fn find_model_evaluation_cache(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        cache_key: &[u8; MODEL_CACHE_KEY_BYTES],
    ) -> Result<Option<ModelEvaluationCacheEntry>, StoreError> {
        let row = sqlx::query(
            "SELECT cache.source_request_id, cache.source_model_call_id,
                    cache.internal_artifact_id, cache.input_artifact_id,
                    cache.output_artifact_id, cache.call_artifact_id,
                    cache.provider, cache.provider_model_id, cache.model_revision,
                    cache.prompt_revision, cache.resolved_model_revision
             FROM xshield.model_evaluation_cache cache
             JOIN xshield.artifact_catalog internal_catalog
               ON internal_catalog.tenant_id=cache.tenant_id
              AND internal_catalog.site_id=cache.site_id
              AND internal_catalog.artifact_id=cache.internal_artifact_id
             JOIN xshield.artifact_catalog input_catalog
               ON input_catalog.tenant_id=cache.tenant_id
              AND input_catalog.site_id=cache.site_id
              AND input_catalog.artifact_id=cache.input_artifact_id
             JOIN xshield.artifact_catalog output_catalog
               ON output_catalog.tenant_id=cache.tenant_id
              AND output_catalog.site_id=cache.site_id
              AND output_catalog.artifact_id=cache.output_artifact_id
             JOIN xshield.artifact_catalog call_catalog
               ON call_catalog.tenant_id=cache.tenant_id
              AND call_catalog.site_id=cache.site_id
              AND call_catalog.artifact_id=cache.call_artifact_id
             WHERE cache.tenant_id=$1 AND cache.site_id=$2
               AND cache.cache_key=$3
               AND cache.expires_at > clock_timestamp()
               AND internal_catalog.status='active'
               AND input_catalog.status='active'
               AND output_catalog.status='active'
               AND call_catalog.status='active'
               AND internal_catalog.deleted_at IS NULL
               AND input_catalog.deleted_at IS NULL
               AND output_catalog.deleted_at IS NULL
               AND call_catalog.deleted_at IS NULL
               AND internal_catalog.expires_at > clock_timestamp()
               AND input_catalog.expires_at > clock_timestamp()
               AND output_catalog.expires_at > clock_timestamp()
               AND call_catalog.expires_at > clock_timestamp()",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(cache_key.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(parse_cache_entry).transpose()
    }

    /// Stores one successful evaluation only while all source catalog rows are
    /// still active and unexpired. Exact retries are idempotent; a key bound to
    /// different source facts is reported as a conflict.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the command is invalid or the transaction
    /// cannot be completed.
    pub async fn store_model_evaluation_cache(
        &self,
        command: ModelEvaluationCacheWrite<'_>,
    ) -> Result<ModelEvaluationCacheWriteOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_cache_timeouts(&mut transaction).await?;
        sqlx::query(
            "DELETE FROM xshield.model_evaluation_cache
             WHERE tenant_id=$1 AND site_id=$2 AND cache_key=$3
               AND expires_at <= clock_timestamp()",
        )
        .bind(command.tenant.as_str())
        .bind(command.site.as_str())
        .bind(command.cache_key.as_slice())
        .execute(&mut *transaction)
        .await?;
        let inserted = sqlx::query(
            "WITH source AS (
                SELECT min(expires_at) AS expires_at
                FROM xshield.artifact_catalog
                WHERE tenant_id=$1 AND site_id=$2
                  AND artifact_id IN ($6,$7,$8,$9)
                  AND status='active' AND deleted_at IS NULL
                  AND expires_at > clock_timestamp()
                HAVING count(*) = 4
             )
             INSERT INTO xshield.model_evaluation_cache (
                tenant_id, site_id, cache_key, source_request_id,
                source_model_call_id, internal_artifact_id, input_artifact_id,
                output_artifact_id, call_artifact_id, provider, provider_model_id,
                model_revision, prompt_revision, resolved_model_revision,
                created_at, expires_at
             )
             SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                    date_trunc('milliseconds', clock_timestamp()),
                    LEAST($15, source.expires_at)
             FROM source
             WHERE $15 > clock_timestamp()
               AND source.expires_at > date_trunc('milliseconds', clock_timestamp())
             ON CONFLICT DO NOTHING",
        )
        .bind(command.tenant.as_str())
        .bind(command.site.as_str())
        .bind(command.cache_key.as_slice())
        .bind(command.source_request.as_str())
        .bind(command.source_model_call.as_str())
        .bind(command.internal_artifact.as_str())
        .bind(command.input_artifact.as_str())
        .bind(command.output_artifact.as_str())
        .bind(command.call_artifact.as_str())
        .bind(command.provider)
        .bind(command.provider_model_id)
        .bind(command.model_revision)
        .bind(command.prompt_revision)
        .bind(command.resolved_model_revision)
        .bind(date_millis(command.expires_at))
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 1 {
            transaction.commit().await?;
            return Ok(ModelEvaluationCacheWriteOutcome::Stored);
        }
        let existing = sqlx::query(
            "SELECT source_request_id, source_model_call_id, internal_artifact_id,
                    input_artifact_id, output_artifact_id, call_artifact_id,
                    provider, provider_model_id, model_revision, prompt_revision,
                    resolved_model_revision
             FROM xshield.model_evaluation_cache
             WHERE tenant_id=$1 AND site_id=$2 AND cache_key=$3
             FOR KEY SHARE",
        )
        .bind(command.tenant.as_str())
        .bind(command.site.as_str())
        .bind(command.cache_key.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = existing else {
            transaction.rollback().await?;
            return Ok(ModelEvaluationCacheWriteOutcome::Conflict);
        };
        let current = parse_cache_entry(&row)?;
        let exact = current.source_request == *command.source_request
            && current.source_model_call == *command.source_model_call
            && current.internal_artifact == *command.internal_artifact
            && current.input_artifact == *command.input_artifact
            && current.output_artifact == *command.output_artifact
            && current.call_artifact == *command.call_artifact
            && current.provider == command.provider
            && current.provider_model_id == command.provider_model_id
            && current.model_revision == command.model_revision
            && current.prompt_revision == command.prompt_revision
            && current.resolved_model_revision.as_deref() == command.resolved_model_revision;
        transaction.commit().await?;
        Ok(if exact {
            ModelEvaluationCacheWriteOutcome::Existing
        } else {
            ModelEvaluationCacheWriteOutcome::Conflict
        })
    }
}

fn parse_cache_entry(row: &sqlx::postgres::PgRow) -> Result<ModelEvaluationCacheEntry, StoreError> {
    let source_request = RequestId::parse(row.try_get::<String, _>("source_request_id")?)
        .map_err(|_| StoreError::CorruptData("model_cache_source_request"))?;
    let source_model_call =
        ModelCallId::parse(row.try_get::<String, _>("source_model_call_id")?)
            .map_err(|_| StoreError::CorruptData("model_cache_source_model_call"))?;
    let parse_artifact = |field: &'static str| {
        ArtifactId::parse(row.try_get::<String, _>(field)?)
            .map_err(|_| StoreError::CorruptData(field))
    };
    let provider: String = row.try_get("provider")?;
    let provider_model_id: String = row.try_get("provider_model_id")?;
    let model_revision: String = row.try_get("model_revision")?;
    let prompt_revision: String = row.try_get("prompt_revision")?;
    let resolved_model_revision: Option<String> = row.try_get("resolved_model_revision")?;
    if !matches!(
        (provider.as_str(), provider_model_id.as_str()),
        ("typesafe", "jev-1.13.0") | ("vercel_ai_gateway", "typesafe-ai/jev")
    ) || !valid_name(&model_revision)
        || !valid_name(&prompt_revision)
        || resolved_model_revision
            .as_deref()
            .is_some_and(|value| !valid_name(value))
    {
        return Err(StoreError::CorruptData("model_cache_identity"));
    }
    Ok(ModelEvaluationCacheEntry {
        source_request,
        source_model_call,
        internal_artifact: parse_artifact("internal_artifact_id")?,
        input_artifact: parse_artifact("input_artifact_id")?,
        output_artifact: parse_artifact("output_artifact_id")?,
        call_artifact: parse_artifact("call_artifact_id")?,
        provider,
        provider_model_id,
        model_revision,
        prompt_revision,
        resolved_model_revision,
    })
}

async fn set_cache_timeouts(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn date_millis(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond(value.timestamp_subsec_millis() * 1_000_000)
        .unwrap_or(value)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
