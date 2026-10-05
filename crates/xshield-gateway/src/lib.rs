//! Validated runtime configuration and deterministic admission for the Pingora edge.

#![warn(missing_docs)]

use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    str::FromStr,
};
use xshield_audit::JournalLimits;
use xshield_core::{
    SitePolicyConfig,
    admission::{
        AdmissionClass, AdmissionProof, AdmissionRequest, CapabilityPolicy, OperationPolicy,
        ResourceAccess,
    },
    audit::ReasonCode,
    domain::{
        ActionId, FieldName, MappingRevision, OperationId, ResourceType, ShareIssuanceRuleId,
        SiteId, TenantId, ViewProfile,
    },
    grant::ResourceKeyHmac,
    identity::UnixSeconds,
    provenance::{ActionTarget, BuildFingerprint, HttpMethod, RouteTemplate},
    site::PortNumber,
};

pub mod auth_binding;
pub mod edge_transport;
pub mod evidence_capture;
pub mod multi_site;
pub mod page_actions;
pub mod proxy_protocol;
pub mod request_crypto;
pub mod response_crypto;
pub mod response_grant;
pub mod sensor;
pub mod sensor_html;
pub mod share_issue;
pub mod share_response;
pub mod share_token;

use auth_binding::{AuthBindingRule, AuthRevokeRule, AuthTransitionRule};
use evidence_capture::{EvidenceCaptureDto, EvidenceCaptureRule};
use request_crypto::{RequestCryptoObserveRule, RequestCryptoPolicy, RequestCryptoRule};
use response_crypto::ResponseCryptoRule;
use response_grant::ResponseGrantRule;
use share_response::ResponseShareRule;

/// Maximum accepted gateway configuration size.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// Maximum complete private JSON response accepted by the MVP adapter.
pub const MAX_BUFFERED_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Maximum serialized direct-encryption response envelope.
pub const MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES: usize = MAX_BUFFERED_JSON_BYTES * 2 + 4096;
// Size-independent adapter metadata, digests, and the AES output block.
const RESPONSE_CRYPTO_FIXED_IN_FLIGHT_BYTES: usize = 4096 + 16;
// Adapter metadata, AAD, digests, and small parser allocations.
const REQUEST_CRYPTO_FIXED_IN_FLIGHT_BYTES: usize = 4096;
/// Aggregate budget covering one maximum encrypted response transformation.
pub const MAX_BUFFERED_BODY_IN_FLIGHT_BYTES: usize = MAX_BUFFERED_JSON_BYTES * 2
    + MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES
    + RESPONSE_CRYPTO_FIXED_IN_FLIGHT_BYTES;
/// Pingora retry-buffer ceiling used to replace a pre-read encrypted entity.
pub const MAX_ENCRYPTED_REQUEST_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_PATH_RESOURCE_OPERATIONS: usize = 64;
const STATIC_ASSET_OPERATION_ID: &str = "site.static_asset";
/// Versioned same-origin browser sensor asset injected into new pages.
pub const SENSOR_ASSET_PATH: &str = "/__xshield/v1/sensor/1.1.0.js";
/// Immutable browser sensor bootstrap loader injected into new pages.
pub const SENSOR_LOADER_PATH: &str = "/__xshield/v1/sensor/1.1.0-loader.js";
/// Exact versioned sensor bytes served by the gateway and bound into HTML SRI.
pub const SENSOR_ASSET_BYTES: &[u8] = include_bytes!("../../../sensor/src/sensor-1.1.0.js");
/// Exact versioned loader bytes served by the gateway and bound into HTML SRI.
pub const SENSOR_LOADER_BYTES: &[u8] = include_bytes!("../../../sensor/src/loader-1.1.0.js");
/// Browser sensor version embedded in [`SENSOR_ASSET_PATH`].
pub const SENSOR_VERSION: &str = "1.1.0";
/// Superseded sensor asset, still served byte-identical: pages delivered by
/// an older edge (or another instance during a rolling upgrade) pin these
/// exact bytes with SRI, so the URL may disappear but must never change.
pub const LEGACY_SENSOR_ASSET_PATH: &str = "/__xshield/v1/sensor/1.0.0.js";
/// Superseded loader asset, still served byte-identical.
pub const LEGACY_SENSOR_LOADER_PATH: &str = "/__xshield/v1/sensor/1.0.0-loader.js";
/// Frozen 1.0.0 sensor bytes.
pub const LEGACY_SENSOR_ASSET_BYTES: &[u8] = include_bytes!("../../../sensor/src/sensor.ts");
/// Frozen 1.0.0 loader bytes.
pub const LEGACY_SENSOR_LOADER_BYTES: &[u8] = include_bytes!("../../../sensor/src/loader.ts");
/// Version embedded in the legacy asset paths.
pub const LEGACY_SENSOR_VERSION: &str = "1.0.0";
/// Dynamic browser sensor bootstrap document.
pub const SENSOR_BOOTSTRAP_PATH: &str = "/__xshield/v1/bootstrap";
/// Same-origin observation preparation endpoint advertised by bootstrap.
pub const SENSOR_PREPARE_PATH: &str = "/__xshield/v1/events/prepare";
/// Observation versions the prepare endpoint accepts: every version whose
/// assets this edge still serves.
pub const ACCEPTED_SENSOR_VERSIONS: [&str; 2] = [SENSOR_VERSION, LEGACY_SENSOR_VERSION];
const SENSOR_ASSET_OPERATION_ID: &str = "xshield.sensor.asset";
const SENSOR_LOADER_OPERATION_ID: &str = "xshield.sensor.loader";
const LEGACY_SENSOR_ASSET_OPERATION_ID: &str = "xshield.sensor.legacy_asset";
const LEGACY_SENSOR_LOADER_OPERATION_ID: &str = "xshield.sensor.legacy_loader";
const SENSOR_BOOTSTRAP_OPERATION_ID: &str = "xshield.sensor.bootstrap";
const SENSOR_PREPARE_OPERATION_ID: &str = "xshield.sensor.prepare";
const INTERNAL_PATH_PREFIX: &str = "/__xshield/";

/// Local edge response selected from the reserved Xshield namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalResponse {
    /// The immutable browser sensor JavaScript asset.
    SensorAsset,
    /// The immutable browser sensor bootstrap loader.
    SensorLoader,
    /// The frozen 1.0.0 sensor asset kept for already-delivered pages.
    LegacySensorAsset,
    /// The frozen 1.0.0 loader asset kept for already-delivered pages.
    LegacySensorLoader,
    /// A per-navigation browser sensor bootstrap document.
    SensorBootstrap,
    /// A session-bound browser observation preparation request.
    SensorPrepare,
}

/// Fully validated gateway configuration selected at process startup.
#[derive(Debug)]
pub struct GatewayConfig {
    listen: SocketAddr,
    origin: Origin,
    tenant_id: TenantId,
    site_id: SiteId,
    policy_revision: xshield_core::domain::PolicyRevision,
    audit: AuditConfig,
    identity_store: Option<IdentityStoreConfig>,
    sensor: Option<SensorConfig>,
    site_policy: Option<SitePolicyConfig>,
    operations: BTreeMap<(String, String), CompiledOperation>,
    path_resource_operations: Vec<CompiledOperation>,
    page_provenance: Option<xshield_core::edge_descriptors::PageProvenance>,
    sensor_routes: page_actions::SensorRoutes,
}

/// Validated server-owned browser sensor bootstrap policy.
#[derive(Clone, Debug)]
pub struct SensorConfig {
    origin: String,
    build_ref: String,
    heartbeat_seconds: u16,
}

#[derive(Debug)]
struct Origin {
    address: SocketAddr,
    server_name: String,
    tls: bool,
}

#[derive(Debug)]
struct AuditConfig {
    directory: PathBuf,
    key_id: String,
    producer_id: String,
    limits: JournalLimits,
    high_watermark_bytes: u64,
    reconcile_max_records: u64,
}

/// Bounded `PostgreSQL` identity lookup settings for protected roots.
#[derive(Clone, Copy, Debug)]
pub struct IdentityStoreConfig {
    max_connections: u32,
    acquire_timeout_ms: u64,
    anonymous_session_ttl_seconds: u64,
    max_active_anonymous_sessions: u32,
    anonymous_session_rate_window_seconds: u64,
    max_anonymous_session_creations_per_source: u32,
    max_anonymous_session_creations_per_site: u32,
}

#[derive(Debug)]
struct CompiledOperation {
    method: HttpMethod,
    route: RouteTemplate,
    route_match: CompiledRouteMatch,
    policy: OperationPolicy,
    source_action: Option<ActionId>,
    resource: Option<CompiledResource>,
    request_crypto: Option<RequestCryptoPolicy>,
    issued_by: Option<xshield_core::edge_descriptors::IssuedBy>,
    response: Option<CompiledResponse>,
}

#[derive(Debug)]
struct CompiledResponse {
    kind: ResponseKind,
    page_actions: Option<xshield_core::edge_descriptors::PageActions>,
    max_bytes: usize,
    crypto: Option<ResponseCryptoRule>,
    grant: Option<ResponseGrantRule>,
    share_issue: Option<ResponseShareRule>,
    auth_binding: Option<AuthBindingRule>,
    auth_revoke: Option<AuthRevokeRule>,
    auth_refresh: Option<AuthTransitionRule>,
    auth_context_switch: Option<AuthTransitionRule>,
    evidence_capture: Option<EvidenceCaptureRule>,
}

#[derive(Debug)]
enum ResponseKind {
    BufferedJson,
    SensorHtml(sensor_html::SensorHtmlRule),
}

struct CompiledOperations {
    exact: BTreeMap<(String, String), CompiledOperation>,
    path_resources: Vec<CompiledOperation>,
}

#[derive(Debug)]
enum CompiledRouteMatch {
    Exact(String),
    FinalResourceSegment { prefix: String },
}

#[derive(Debug)]
struct CompiledResource {
    resource_type: ResourceType,
    view_profile: ViewProfile,
    location: CompiledResourceLocation,
}

#[derive(Debug)]
enum CompiledResourceLocation {
    Query(FieldName),
    FinalPathSegment {
        prefix: String,
        parameter: FieldName,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDto {
    listen: String,
    origin: OriginDto,
    tenant_id: String,
    site_id: String,
    policy_revision: String,
    audit: AuditDto,
    #[serde(default)]
    identity_store: Option<IdentityStoreDto>,
    #[serde(default)]
    sensor: Option<SensorDto>,
    #[serde(default)]
    site_policy: Option<SitePolicyConfig>,
    operations: Vec<OperationDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorDto {
    origin: String,
    build_ref: String,
    heartbeat_seconds: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditDto {
    directory: String,
    key_id: String,
    producer_id: String,
    max_bytes: u64,
    high_watermark_bytes: u64,
    segment_max_bytes: u64,
    #[serde(default = "default_reconcile_max_records")]
    reconcile_max_records: u64,
}

const fn default_reconcile_max_records() -> u64 {
    1_000_000
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityStoreDto {
    max_connections: u32,
    acquire_timeout_ms: u64,
    #[serde(default = "default_anonymous_session_ttl_seconds")]
    anonymous_session_ttl_seconds: u64,
    #[serde(default = "default_max_active_anonymous_sessions")]
    max_active_anonymous_sessions: u32,
    #[serde(default = "default_anonymous_session_rate_window_seconds")]
    anonymous_session_rate_window_seconds: u64,
    #[serde(default = "default_max_anonymous_session_creations_per_source")]
    max_anonymous_session_creations_per_source: u32,
    #[serde(default = "default_max_anonymous_session_creations_per_site")]
    max_anonymous_session_creations_per_site: u32,
}

const fn default_anonymous_session_ttl_seconds() -> u64 {
    3_600
}

const fn default_max_active_anonymous_sessions() -> u32 {
    100_000
}

const fn default_anonymous_session_rate_window_seconds() -> u64 {
    60
}

const fn default_max_anonymous_session_creations_per_source() -> u32 {
    10
}

const fn default_max_anonymous_session_creations_per_site() -> u32 {
    1_000
}

fn validate_identity_store(
    identity: &IdentityStoreDto,
) -> Result<IdentityStoreConfig, ConfigError> {
    let active_windows = identity
        .anonymous_session_ttl_seconds
        .div_ceil(identity.anonymous_session_rate_window_seconds.max(1))
        .saturating_add(1);
    if identity.max_connections == 0
        || identity.max_connections > 64
        || identity.acquire_timeout_ms == 0
        || identity.acquire_timeout_ms > 30_000
        || identity.anonymous_session_ttl_seconds == 0
        || identity.anonymous_session_ttl_seconds > 86_400
        || identity.max_active_anonymous_sessions == 0
        || identity.max_active_anonymous_sessions > 1_000_000
        || identity.anonymous_session_rate_window_seconds == 0
        || identity.anonymous_session_rate_window_seconds > 3_600
        || identity.max_anonymous_session_creations_per_source == 0
        || identity.max_anonymous_session_creations_per_source
            > identity.max_anonymous_session_creations_per_site
        || identity.max_anonymous_session_creations_per_site == 0
        || identity.max_anonymous_session_creations_per_site > 1_000_000
        || u64::from(identity.max_anonymous_session_creations_per_site)
            .saturating_mul(active_windows)
            > u64::from(identity.max_active_anonymous_sessions)
    {
        return Err(ConfigError::Invalid("identity_store"));
    }
    Ok(IdentityStoreConfig {
        max_connections: identity.max_connections,
        acquire_timeout_ms: identity.acquire_timeout_ms,
        anonymous_session_ttl_seconds: identity.anonymous_session_ttl_seconds,
        max_active_anonymous_sessions: identity.max_active_anonymous_sessions,
        anonymous_session_rate_window_seconds: identity.anonymous_session_rate_window_seconds,
        max_anonymous_session_creations_per_source: identity
            .max_anonymous_session_creations_per_source,
        max_anonymous_session_creations_per_site: identity.max_anonymous_session_creations_per_site,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginDto {
    address: String,
    server_name: String,
    tls: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationDto {
    operation_id: String,
    method: String,
    path: String,
    admission: AdmissionDto,
    source_action: Option<String>,
    resource_type: Option<String>,
    view_profile: Option<String>,
    resource_query_parameter: Option<String>,
    resource_path_parameter: Option<String>,
    #[serde(default)]
    request_crypto: Option<RequestCryptoDto>,
    #[serde(default)]
    issued_by: Option<page_actions::IssuedByDto>,
    response: Option<ResponseDto>,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum RequestCryptoDto {
    DirectDecrypt {
        adapter_revision: String,
        key_id: String,
        key_not_before: u64,
        key_expires_at: u64,
        max_envelope_bytes: usize,
        max_plaintext_bytes: usize,
        max_message_age_seconds: u64,
        max_future_skew_seconds: u64,
        max_active_messages: u32,
    },
    Observe {
        adapter_revision: String,
    },
    Compatibility {
        adapter_revision: String,
        approval_ref: String,
        expires_at: u64,
        build_fingerprints: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseDto {
    mode: ResponseModeDto,
    max_bytes: usize,
    #[serde(default)]
    adapter_revision: Option<String>,
    #[serde(default)]
    origin_sha256: Option<String>,
    #[serde(default)]
    injection_offset: Option<usize>,
    #[serde(default)]
    additional_adapters: Vec<SensorHtmlAdapterDto>,
    #[serde(default)]
    page_actions: Option<page_actions::PageActionsDto>,
    #[serde(default)]
    crypto: Option<ResponseCryptoDto>,
    #[serde(default)]
    resource_grant: Option<ResponseGrantDto>,
    #[serde(default)]
    share_issue: Option<ResponseShareDto>,
    #[serde(default)]
    auth_binding: Option<AuthBindingDto>,
    #[serde(default)]
    auth_revoke: Option<AuthRevokeDto>,
    #[serde(default)]
    auth_refresh: Option<AuthRefreshDto>,
    #[serde(default)]
    auth_context_switch: Option<AuthRefreshDto>,
    #[serde(default)]
    evidence_capture: Option<EvidenceCaptureDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorHtmlAdapterDto {
    adapter_revision: String,
    origin_sha256: String,
    injection_offset: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseCryptoDto {
    mode: ResponseCryptoModeDto,
    adapter_revision: String,
    key_id: String,
    key_not_before: u64,
    key_expires_at: u64,
    message_ttl_seconds: u64,
    max_envelope_bytes: usize,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ResponseCryptoModeDto {
    DirectEncrypt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthBindingDto {
    success_status: u16,
    principal_pointer: String,
    authorization_context_pointer: String,
    bearer_pointer: String,
    credential_ttl_seconds: u64,
    session_ttl_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthRefreshDto {
    success_status: u16,
    principal_pointer: String,
    authorization_context_pointer: String,
    bearer_pointer: String,
    credential_ttl_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthRevokeDto {
    success_status: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseGrantDto {
    success_status: u16,
    items_pointer: String,
    resource_pointer: String,
    action_ref_field: String,
    target_operation_id: String,
    target_mapping_revision: String,
    ttl_seconds: u64,
    max_items: usize,
    max_active_grants: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseShareDto {
    success_status: u16,
    token_field: String,
    target_operation_id: String,
    issuance_rule_id: String,
    ttl_seconds: u64,
    max_active_shares: u32,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ResponseModeDto {
    BufferedJson,
    SensorHtml,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AdmissionDto {
    Public,
    #[serde(rename = "AUTH_ENTRY")]
    AuthenticationEntry,
    AuthenticatedRoot,
    UiActionRequired,
    ShareEntry,
    ServiceIdentity,
}

impl GatewayConfig {
    /// Parses a bounded JSON DTO and validates every trust-boundary field.
    ///
    /// # Errors
    /// Returns [`ConfigError`] for malformed JSON, invalid identifiers, unsafe
    /// network values, unsafe paths, incoherent policies, or ambiguous routes.
    #[allow(clippy::too_many_lines)]
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid("configuration size"));
        }
        let dto: ConfigDto = serde_json::from_slice(bytes).map_err(ConfigError::Json)?;
        if let Some(policy) = dto.site_policy.as_ref() {
            policy
                .validate()
                .map_err(|_| ConfigError::Invalid("site_policy"))?;
        }
        let listen: SocketAddr = dto
            .listen
            .parse()
            .map_err(|_| ConfigError::Invalid("listen"))?;
        PortNumber::parse(listen.port()).map_err(|_| ConfigError::Invalid("listen.port"))?;
        let origin_address = dto
            .origin
            .address
            .parse()
            .map_err(|_| ConfigError::Invalid("origin.address"))?;
        if !valid_server_name(&dto.origin.server_name) {
            return Err(ConfigError::Invalid("origin.server_name"));
        }
        let tenant_id = TenantId::parse(dto.tenant_id).map_err(ConfigError::Domain)?;
        let site_id = SiteId::parse(dto.site_id).map_err(ConfigError::Domain)?;
        let policy_revision = xshield_core::domain::PolicyRevision::parse(dto.policy_revision)
            .map_err(ConfigError::Domain)?;
        let audit_directory = validate_audit_directory(dto.audit.directory)?;
        if !valid_scoped_value(&dto.audit.key_id) {
            return Err(ConfigError::Invalid("audit.key_id"));
        }
        if !valid_scoped_value(&dto.audit.producer_id) {
            return Err(ConfigError::Invalid("audit.producer_id"));
        }
        let audit_limits = JournalLimits::new(
            dto.audit.max_bytes,
            dto.audit.high_watermark_bytes,
            dto.audit.segment_max_bytes,
        )
        .map_err(ConfigError::Journal)?;
        if dto.audit.reconcile_max_records == 0 || dto.audit.reconcile_max_records > 10_000_000 {
            return Err(ConfigError::Invalid("audit.reconcile_max_records"));
        }
        let identity_store = dto
            .identity_store
            .as_ref()
            .map(validate_identity_store)
            .transpose()?;
        let sensor = dto.sensor.map(validate_sensor).transpose()?;
        let compiled_operations = compile_operations(dto.operations)?;
        if sensor.is_none()
            && compiled_operations
                .exact
                .values()
                .chain(compiled_operations.path_resources.iter())
                .any(|operation| {
                    operation.response.as_ref().is_some_and(|response| {
                        matches!(response.kind, ResponseKind::SensorHtml(_))
                    })
                })
        {
            return Err(ConfigError::Invalid("sensor"));
        }
        if identity_store.is_none()
            && (sensor.is_some()
                || compiled_operations
                    .exact
                    .values()
                    .chain(compiled_operations.path_resources.iter())
                    .any(|operation| {
                        matches!(
                            operation.policy.admission_class(),
                            AdmissionClass::AuthenticatedRoot
                                | AdmissionClass::UiActionRequired
                                | AdmissionClass::ShareEntry
                                | AdmissionClass::ServiceIdentity
                        ) || operation.response.as_ref().is_some_and(|response| {
                            response.auth_binding.is_some()
                                || response.auth_revoke.is_some()
                                || response.evidence_capture.is_some()
                        }) || operation.request_crypto.is_some()
                    }))
        {
            return Err(ConfigError::Invalid("identity_store"));
        }
        let all_operations = compiled_operations
            .exact
            .values()
            .chain(compiled_operations.path_resources.iter())
            .collect::<Vec<_>>();
        let page_provenance = page_actions::compile(&all_operations, &policy_revision)?;
        let sensor_routes = page_actions::sensor_routes(&all_operations)?;
        Ok(Self {
            listen,
            origin: Origin {
                address: origin_address,
                server_name: dto.origin.server_name,
                tls: dto.origin.tls,
            },
            tenant_id,
            site_id,
            policy_revision,
            audit: AuditConfig {
                directory: audit_directory,
                key_id: dto.audit.key_id,
                producer_id: dto.audit.producer_id,
                limits: audit_limits,
                high_watermark_bytes: dto.audit.high_watermark_bytes,
                reconcile_max_records: dto.audit.reconcile_max_records,
            },
            identity_store,
            sensor,
            site_policy: dto.site_policy,
            operations: compiled_operations.exact,
            path_resource_operations: compiled_operations.path_resources,
            page_provenance,
            sensor_routes,
        })
    }

    /// Returns the actions an approved `SENSOR_HTML` page root issues on
    /// delivery, or `None` when the exact operation is not such a page root.
    #[must_use]
    pub fn page_action_plan(
        &self,
        method: &str,
        path: &str,
    ) -> Option<&page_actions::PageActionPlan> {
        let operation = self.operation(method, path)?;
        self.page_provenance
            .as_ref()?
            .plan(operation.policy.operation_id())
    }

    /// Returns the digest-bound descriptors the edge must provision before
    /// this configuration serves traffic; `None` keeps external provisioning.
    #[must_use]
    pub fn edge_descriptors(&self) -> Option<&page_actions::EdgeDescriptorSet> {
        self.page_provenance
            .as_ref()
            .map(xshield_core::edge_descriptors::PageProvenance::descriptors)
    }

    /// Returns non-secret routing hints the browser sensor receives at bootstrap.
    #[must_use]
    pub const fn sensor_routes(&self) -> &page_actions::SensorRoutes {
        &self.sensor_routes
    }

    /// Returns the validated listener socket.
    #[must_use]
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Returns the fixed upstream socket selected by trusted configuration.
    #[must_use]
    pub const fn origin_address(&self) -> SocketAddr {
        self.origin.address
    }

    /// Returns the validated upstream TLS and Host name.
    #[must_use]
    pub fn origin_server_name(&self) -> &str {
        &self.origin.server_name
    }

    /// Returns whether the fixed upstream uses TLS.
    #[must_use]
    pub const fn origin_tls(&self) -> bool {
        self.origin.tls
    }

    /// Returns the tenant selected by trusted startup configuration.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the site selected by trusted startup configuration.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the immutable policy revision used for every request.
    #[must_use]
    pub const fn policy_revision(&self) -> &xshield_core::domain::PolicyRevision {
        &self.policy_revision
    }

    /// Returns the private local journal directory.
    #[must_use]
    pub fn audit_directory(&self) -> &Path {
        &self.audit.directory
    }

    /// Returns the identifier for the externally supplied journal key.
    #[must_use]
    pub fn audit_key_id(&self) -> &str {
        &self.audit.key_id
    }

    /// Returns the deployment-scoped audit producer identifier.
    #[must_use]
    pub fn audit_producer_id(&self) -> &str {
        &self.audit.producer_id
    }

    /// Returns the validated journal capacity settings.
    #[must_use]
    pub const fn audit_limits(&self) -> JournalLimits {
        self.audit.limits
    }

    /// Returns the journal size below which a failed durable-audit barrier may
    /// reopen; staying under the warning threshold avoids reopening into a
    /// journal that would immediately fail again.
    #[must_use]
    pub const fn audit_high_watermark_bytes(&self) -> u64 {
        self.audit.high_watermark_bytes
    }

    /// Returns the startup ceiling for authenticated historical record scans.
    #[must_use]
    pub const fn audit_reconcile_max_records(&self) -> u64 {
        self.audit.reconcile_max_records
    }

    /// Returns bounded identity-store settings when protected roots are enabled.
    #[must_use]
    pub const fn identity_store(&self) -> Option<IdentityStoreConfig> {
        self.identity_store
    }

    /// Returns the typed site policy carried by this immutable snapshot.
    #[must_use]
    pub fn site_policy(&self) -> Option<&SitePolicyConfig> {
        self.site_policy.as_ref()
    }

    /// Returns the site-wide request entity limit used before forwarding.
    #[must_use]
    pub fn request_body_limit(&self) -> usize {
        self.site_policy
            .as_ref()
            .map_or(16 * 1024 * 1024, |policy| {
                policy.limits.max_request_body_bytes
            })
    }

    /// Returns the optional browser sensor bootstrap policy.
    #[must_use]
    pub const fn sensor(&self) -> Option<&SensorConfig> {
        self.sensor.as_ref()
    }

    /// Admits the reserved prepare operation after the identity adapter loaded
    /// an exact current WAF session.
    ///
    /// The result authorizes metadata ingestion only. It is not an
    /// [`AdmissionProof`] and cannot admit a configured business operation.
    #[must_use]
    pub fn admit_sensor_session(&self, method: &str, path: &str) -> GatewayDecision {
        if self.internal_response(method, path) != Some(InternalResponse::SensorPrepare) {
            return GatewayDecision {
                outcome: GatewayOutcome::Denied,
                operation_id: None,
                reason_code: ReasonCode::OperationNotMatched,
            };
        }
        match OperationId::parse(SENSOR_PREPARE_OPERATION_ID) {
            Ok(operation_id) => GatewayDecision {
                outcome: GatewayOutcome::Allowed,
                operation_id: Some(operation_id),
                reason_code: ReasonCode::SensorObservationAccepted,
            },
            Err(_) => GatewayDecision {
                outcome: GatewayOutcome::Denied,
                operation_id: None,
                reason_code: ReasonCode::RequestIncomplete,
            },
        }
    }

    /// Returns whether request admission or response binding needs identity state.
    #[must_use]
    pub fn requires_identity_runtime(&self) -> bool {
        self.sensor.is_some()
            || self
                .operations
                .values()
                .chain(self.path_resource_operations.iter())
                .any(|operation| {
                    matches!(
                        operation.policy.admission_class(),
                        AdmissionClass::AuthenticatedRoot
                            | AdmissionClass::UiActionRequired
                            | AdmissionClass::ShareEntry
                            | AdmissionClass::ServiceIdentity
                    ) || operation.response.as_ref().is_some_and(|response| {
                        response.auth_binding.is_some() || response.auth_revoke.is_some()
                    })
                })
    }

    /// Applies the compiled exact-operation policy with no client-created proof.
    ///
    /// Protected entries fail closed until their authoritative proof loader
    /// invokes one of the proof-bearing admission methods.
    #[must_use]
    pub fn admit(&self, method: &str, path: &str, now: UnixSeconds) -> GatewayDecision {
        self.admit_with_proof(method, path, now, AdmissionProof::None)
    }

    /// Returns the proof class for an exact configured operation.
    #[must_use]
    pub fn admission_class(&self, method: &str, path: &str) -> Option<AdmissionClass> {
        if let Some(response) = self.internal_response(method, path) {
            return Some(match response {
                InternalResponse::SensorPrepare => AdmissionClass::AuthenticatedRoot,
                InternalResponse::SensorAsset
                | InternalResponse::SensorLoader
                | InternalResponse::LegacySensorAsset
                | InternalResponse::LegacySensorLoader
                | InternalResponse::SensorBootstrap => AdmissionClass::Public,
            });
        }
        self.operation(method, path)
            .map(|operation| operation.policy.admission_class())
    }

    /// Returns a server-owned response for an exact reserved route.
    #[must_use]
    pub fn internal_response(&self, method: &str, path: &str) -> Option<InternalResponse> {
        match (method, path) {
            ("GET", SENSOR_ASSET_PATH) => Some(InternalResponse::SensorAsset),
            ("GET", SENSOR_LOADER_PATH) => Some(InternalResponse::SensorLoader),
            ("GET", LEGACY_SENSOR_ASSET_PATH) => Some(InternalResponse::LegacySensorAsset),
            ("GET", LEGACY_SENSOR_LOADER_PATH) => Some(InternalResponse::LegacySensorLoader),
            ("GET", SENSOR_BOOTSTRAP_PATH) if self.sensor.is_some() => {
                Some(InternalResponse::SensorBootstrap)
            }
            ("POST", SENSOR_PREPARE_PATH) if self.sensor.is_some() => {
                Some(InternalResponse::SensorPrepare)
            }
            _ => None,
        }
    }

    /// Returns the trusted query or path adapter for a matched resource operation.
    #[must_use]
    pub fn resource_operation(&self, method: &str, path: &str) -> Option<ResourceOperation<'_>> {
        let operation = self.operation(method, path)?;
        let resource = operation.resource.as_ref()?;
        Some(ResourceOperation {
            operation_id: operation.policy.operation_id(),
            resource_type: &resource.resource_type,
            view_profile: &resource.view_profile,
            location: match &resource.location {
                CompiledResourceLocation::Query(parameter) => ResourceLocation::Query(parameter),
                CompiledResourceLocation::FinalPathSegment { prefix, parameter } => {
                    ResourceLocation::FinalPathSegment { prefix, parameter }
                }
            },
        })
    }

    /// Returns the complete-buffer limit for an exact private JSON response.
    #[must_use]
    pub fn buffered_json_max_bytes(&self, method: &str, path: &str) -> Option<usize> {
        let response = self.operation(method, path)?.response.as_ref()?;
        matches!(response.kind, ResponseKind::BufferedJson).then_some(response.max_bytes)
    }

    /// Returns the complete-buffer response policy for one exact operation.
    #[must_use]
    pub fn buffered_response_policy(
        &self,
        method: &str,
        path: &str,
    ) -> Option<BufferedResponsePolicy<'_>> {
        let response = self.operation(method, path)?.response.as_ref()?;
        Some(match &response.kind {
            ResponseKind::BufferedJson => BufferedResponsePolicy::Json {
                max_bytes: response.max_bytes,
            },
            ResponseKind::SensorHtml(rule) => BufferedResponsePolicy::SensorHtml(rule),
        })
    }

    /// Returns the server-selected request decryption rule for an exact operation.
    #[must_use]
    pub fn request_crypto_policy(&self, method: &str, path: &str) -> Option<&RequestCryptoPolicy> {
        self.operation(method, path)?.request_crypto.as_ref()
    }

    /// Returns the mandatory decryption rule for an exact enforce operation.
    #[must_use]
    pub fn request_crypto_rule(&self, method: &str, path: &str) -> Option<&RequestCryptoRule> {
        match self.request_crypto_policy(method, path)? {
            RequestCryptoPolicy::Enforce(rule) => Some(rule),
            RequestCryptoPolicy::Observe(_) | RequestCryptoPolicy::Compatibility(_) => None,
        }
    }

    /// Returns the sole request-decryption key identifier required at startup.
    #[must_use]
    pub fn request_crypto_key_id(&self) -> Option<&str> {
        self.operations
            .values()
            .chain(self.path_resource_operations.iter())
            .find_map(|operation| match operation.request_crypto.as_ref()? {
                RequestCryptoPolicy::Enforce(rule) => Some(rule.key_id()),
                RequestCryptoPolicy::Observe(_) | RequestCryptoPolicy::Compatibility(_) => None,
            })
    }

    /// Returns the response encryption rule for one exact operation.
    #[must_use]
    pub fn response_crypto_rule(&self, method: &str, path: &str) -> Option<&ResponseCryptoRule> {
        self.operation(method, path)?
            .response
            .as_ref()?
            .crypto
            .as_ref()
    }

    /// Returns the approved evidence-copy policy for this operation's JSON response.
    #[must_use]
    pub fn evidence_capture_rule(&self, method: &str, path: &str) -> Option<&EvidenceCaptureRule> {
        self.operation(method, path)?
            .response
            .as_ref()?
            .evidence_capture
            .as_ref()
    }

    /// Whether startup must open the bounded evidence writer and catalog store.
    #[must_use]
    pub fn requires_evidence_capture(&self) -> bool {
        self.operations
            .values()
            .chain(self.path_resource_operations.iter())
            .any(|operation| {
                operation
                    .response
                    .as_ref()
                    .is_some_and(|response| response.evidence_capture.is_some())
            })
    }

    /// Returns the sole response-encryption key identifier required at startup.
    #[must_use]
    pub fn response_crypto_key_id(&self) -> Option<&str> {
        self.operations
            .values()
            .chain(self.path_resource_operations.iter())
            .find_map(|operation| {
                operation
                    .response
                    .as_ref()?
                    .crypto
                    .as_ref()
                    .map(ResponseCryptoRule::key_id)
            })
    }

    /// Returns one validated response extraction rule and its exact target operation.
    #[must_use]
    pub fn response_grant_operation(
        &self,
        method: &str,
        path: &str,
    ) -> Option<ResponseGrantOperation<'_>> {
        let rule = self
            .operation(method, path)?
            .response
            .as_ref()?
            .grant
            .as_ref()?;
        let target = self.operation_by_id(rule.target_operation_id())?;
        let resource = target.resource.as_ref()?;
        let target_field = match &resource.location {
            CompiledResourceLocation::Query(parameter)
            | CompiledResourceLocation::FinalPathSegment { parameter, .. } => parameter,
        };
        Some(ResponseGrantOperation {
            rule,
            target_action_id: target.source_action.as_ref()?,
            target_mapping_revision: rule.target_mapping_revision(),
            resource_type: &resource.resource_type,
            view_profile: &resource.view_profile,
            target_field,
        })
    }

    /// Returns the fixed share scope compiled for one qualified source operation.
    #[must_use]
    pub fn response_share_operation(
        &self,
        method: &str,
        path: &str,
    ) -> Option<ResponseShareOperation<'_>> {
        let source = self.operation(method, path)?;
        let rule = source.response.as_ref()?.share_issue.as_ref()?;
        let target = self.operation_by_id(rule.target_operation_id())?;
        let resource = target.resource.as_ref()?;
        Some(ResponseShareOperation {
            rule,
            source_operation_id: source.policy.operation_id(),
            source_view_profile: &source.resource.as_ref()?.view_profile,
            resource_type: &resource.resource_type,
            view_profile: &resource.view_profile,
        })
    }

    /// Whether startup requires the dedicated share-token derivation key.
    #[must_use]
    pub fn requires_share_issuance(&self) -> bool {
        self.operations
            .values()
            .chain(self.path_resource_operations.iter())
            .any(|operation| {
                operation
                    .response
                    .as_ref()
                    .is_some_and(|response| response.share_issue.is_some())
            })
    }

    /// Returns the authentication-response rule for one exact entry operation.
    #[must_use]
    pub fn auth_binding_rule(&self, method: &str, path: &str) -> Option<&AuthBindingRule> {
        self.operation(method, path)?
            .response
            .as_ref()?
            .auth_binding
            .as_ref()
    }

    /// Returns the explicit logout/revocation response rule for one exact operation.
    #[must_use]
    pub fn auth_revoke_rule(&self, method: &str, path: &str) -> Option<&AuthRevokeRule> {
        self.operation(method, path)?
            .response
            .as_ref()?
            .auth_revoke
            .as_ref()
    }

    /// Returns the same-context authentication refresh rule for one exact operation.
    #[must_use]
    pub fn auth_refresh_rule(&self, method: &str, path: &str) -> Option<&AuthTransitionRule> {
        self.operation(method, path)?
            .response
            .as_ref()?
            .auth_refresh
            .as_ref()
    }

    /// Returns the account-context transition rule for one exact operation.
    #[must_use]
    pub fn auth_context_switch_rule(
        &self,
        method: &str,
        path: &str,
    ) -> Option<&AuthTransitionRule> {
        self.operation(method, path)?
            .response
            .as_ref()?
            .auth_context_switch
            .as_ref()
    }

    /// Applies the compiled exact-operation policy with authoritative loaded proof.
    #[must_use]
    pub fn admit_with_proof(
        &self,
        method: &str,
        path: &str,
        now: UnixSeconds,
        proof: AdmissionProof<'_>,
    ) -> GatewayDecision {
        let target = ActionTarget::None;
        let fields = BTreeSet::new();
        self.admit_scoped_with_proof(method, path, now, &target, &fields, None, proof)
    }

    /// Applies policy to request facts extracted by a trusted route adapter.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn admit_scoped_with_proof(
        &self,
        method: &str,
        path: &str,
        now: UnixSeconds,
        target: &ActionTarget,
        fields: &BTreeSet<FieldName>,
        resource_key: Option<&ResourceKeyHmac>,
        proof: AdmissionProof<'_>,
    ) -> GatewayDecision {
        if let Some(response) = self.internal_response(method, path) {
            let operation = match response {
                InternalResponse::SensorAsset => SENSOR_ASSET_OPERATION_ID,
                InternalResponse::SensorLoader => SENSOR_LOADER_OPERATION_ID,
                InternalResponse::LegacySensorAsset => LEGACY_SENSOR_ASSET_OPERATION_ID,
                InternalResponse::LegacySensorLoader => LEGACY_SENSOR_LOADER_OPERATION_ID,
                InternalResponse::SensorBootstrap => SENSOR_BOOTSTRAP_OPERATION_ID,
                InternalResponse::SensorPrepare => {
                    return GatewayDecision {
                        outcome: GatewayOutcome::Denied,
                        operation_id: OperationId::parse(SENSOR_PREPARE_OPERATION_ID).ok(),
                        reason_code: ReasonCode::AuthRequired,
                    };
                }
            };
            return match OperationId::parse(operation) {
                Ok(operation_id) => GatewayDecision {
                    outcome: GatewayOutcome::Allowed,
                    operation_id: Some(operation_id),
                    reason_code: ReasonCode::PublicEntryAllowed,
                },
                Err(_) => GatewayDecision {
                    outcome: GatewayOutcome::Denied,
                    operation_id: None,
                    reason_code: ReasonCode::RequestIncomplete,
                },
            };
        }
        let Some(operation) = self.operation(method, path) else {
            if self
                .site_policy
                .as_ref()
                .is_some_and(|policy| policy.allows_static_asset(method, path))
            {
                return GatewayDecision {
                    outcome: GatewayOutcome::Allowed,
                    operation_id: OperationId::parse(STATIC_ASSET_OPERATION_ID).ok(),
                    reason_code: ReasonCode::PublicEntryAllowed,
                };
            }
            return GatewayDecision {
                outcome: GatewayOutcome::Denied,
                operation_id: None,
                reason_code: ReasonCode::OperationNotMatched,
            };
        };
        let resource = operation.resource.as_ref().and_then(|resource| {
            resource_key.map(|resource_key| ResourceAccess {
                resource_type: &resource.resource_type,
                resource_key,
            })
        });
        let request = AdmissionRequest {
            tenant_id: &self.tenant_id,
            site_id: &self.site_id,
            method: operation.method,
            route: &operation.route,
            target,
            fields,
            resource,
            now,
        };
        match operation.policy.admit(request, proof) {
            Ok(decision) => GatewayDecision {
                outcome: GatewayOutcome::Allowed,
                operation_id: Some(decision.operation_id),
                reason_code: decision.reason_code,
            },
            Err(error) => GatewayDecision {
                outcome: GatewayOutcome::Denied,
                operation_id: Some(operation.policy.operation_id().clone()),
                reason_code: error.reason_code(),
            },
        }
    }

    fn operation(&self, method: &str, path: &str) -> Option<&CompiledOperation> {
        self.operations
            .get(&(method.to_owned(), path.to_owned()))
            .or_else(|| {
                self.path_resource_operations
                    .iter()
                    .find(|operation| operation.matches_text(method, path))
            })
    }

    fn operation_by_id(&self, operation_id: &OperationId) -> Option<&CompiledOperation> {
        self.operations
            .values()
            .chain(self.path_resource_operations.iter())
            .find(|operation| operation.policy.operation_id() == operation_id)
    }
}

fn compile_operations(operations: Vec<OperationDto>) -> Result<CompiledOperations, ConfigError> {
    if operations.is_empty() {
        return Err(ConfigError::Invalid("operations"));
    }
    let mut exact = BTreeMap::new();
    let mut path_resources = Vec::new();
    let mut operation_ids = BTreeSet::new();
    for operation in operations {
        let compiled = compile_operation(operation)?;
        if !operation_ids.insert(compiled.policy.operation_id().clone()) {
            return Err(ConfigError::Invalid("operations.operation_id"));
        }
        match &compiled.route_match {
            CompiledRouteMatch::Exact(path) => {
                let path = path.clone();
                if path_resources
                    .iter()
                    .any(|candidate: &CompiledOperation| candidate.matches(compiled.method, &path))
                    || exact
                        .insert((compiled.method.as_str().to_owned(), path), compiled)
                        .is_some()
                {
                    return Err(ConfigError::DuplicateRoute);
                }
            }
            CompiledRouteMatch::FinalResourceSegment { prefix } => {
                if path_resources.len() >= MAX_PATH_RESOURCE_OPERATIONS {
                    return Err(ConfigError::Invalid("operations"));
                }
                if path_resources.iter().any(|candidate| {
                    candidate.method == compiled.method
                        && matches!(
                            &candidate.route_match,
                            CompiledRouteMatch::FinalResourceSegment {
                                prefix: candidate_prefix
                            } if candidate_prefix == prefix
                        )
                }) || exact.iter().any(|((method, path), _)| {
                    method == compiled.method.as_str() && compiled.matches(compiled.method, path)
                }) {
                    return Err(ConfigError::DuplicateRoute);
                }
                path_resources.push(compiled);
            }
        }
    }
    let request_key_ids = exact
        .values()
        .chain(path_resources.iter())
        .filter_map(|operation| {
            operation
                .request_crypto
                .as_ref()
                .and_then(|policy| match policy {
                    RequestCryptoPolicy::Enforce(rule) => Some(rule.key_id()),
                    RequestCryptoPolicy::Observe(_) | RequestCryptoPolicy::Compatibility(_) => None,
                })
        })
        .collect::<BTreeSet<_>>();
    if request_key_ids.len() > 1 {
        return Err(ConfigError::Invalid("operations.request_crypto.key_id"));
    }
    let response_key_ids = exact
        .values()
        .chain(path_resources.iter())
        .filter_map(|operation| operation.response.as_ref()?.crypto.as_ref())
        .map(ResponseCryptoRule::key_id)
        .collect::<BTreeSet<_>>();
    if response_key_ids.len() > 1 {
        return Err(ConfigError::Invalid("operations.response.crypto.key_id"));
    }
    if request_key_ids
        .iter()
        .any(|key_id| response_key_ids.contains(key_id))
    {
        return Err(ConfigError::Invalid("operations.response.crypto.key_id"));
    }
    validate_response_contracts(&exact, &path_resources)?;
    Ok(CompiledOperations {
        exact,
        path_resources,
    })
}

fn validate_response_contracts(
    exact: &BTreeMap<(String, String), CompiledOperation>,
    path_resources: &[CompiledOperation],
) -> Result<(), ConfigError> {
    let operations = exact.values().chain(path_resources);
    for source in operations.clone() {
        validate_response_share_contract(source, exact, path_resources)?;
        if source
            .response
            .as_ref()
            .is_some_and(|response| response.auth_binding.is_some())
            && source.policy.admission_class() != AdmissionClass::AuthenticationEntry
        {
            return Err(ConfigError::Invalid("operations.response.auth_binding"));
        }
        if source
            .response
            .as_ref()
            .is_some_and(|response| response.auth_refresh.is_some())
            && source.policy.admission_class() != AdmissionClass::AuthenticatedRoot
        {
            return Err(ConfigError::Invalid("operations.response.auth_refresh"));
        }
        if source
            .response
            .as_ref()
            .is_some_and(|response| response.auth_context_switch.is_some())
            && source.policy.admission_class() != AdmissionClass::AuthenticatedRoot
        {
            return Err(ConfigError::Invalid(
                "operations.response.auth_context_switch",
            ));
        }
        if source
            .response
            .as_ref()
            .is_some_and(|response| response.auth_revoke.is_some())
            && source.policy.admission_class() != AdmissionClass::AuthenticatedRoot
        {
            return Err(ConfigError::Invalid("operations.response.auth_revoke"));
        }
        let Some(rule) = source
            .response
            .as_ref()
            .and_then(|response| response.grant.as_ref())
        else {
            continue;
        };
        if !matches!(
            source.policy.admission_class(),
            AdmissionClass::AuthenticatedRoot | AdmissionClass::UiActionRequired
        ) {
            return Err(ConfigError::Invalid("operations.response.resource_grant"));
        }
        let target = operations
            .clone()
            .find(|operation| operation.policy.operation_id() == rule.target_operation_id())
            .ok_or(ConfigError::Invalid(
                "operations.response.target_operation_id",
            ))?;
        if target.policy.admission_class() != AdmissionClass::UiActionRequired
            || target.source_action.is_none()
            || target.resource.is_none()
        {
            return Err(ConfigError::Invalid(
                "operations.response.target_operation_id",
            ));
        }
    }
    Ok(())
}

fn validate_response_share_contract(
    source: &CompiledOperation,
    exact: &BTreeMap<(String, String), CompiledOperation>,
    path_resources: &[CompiledOperation],
) -> Result<(), ConfigError> {
    let Some(rule) = source
        .response
        .as_ref()
        .and_then(|response| response.share_issue.as_ref())
    else {
        return Ok(());
    };
    let source_resource = source
        .resource
        .as_ref()
        .filter(|_| {
            source.policy.admission_class() == AdmissionClass::UiActionRequired
                && source.method == HttpMethod::Get
                && source.source_action.is_some()
        })
        .ok_or(ConfigError::Invalid("operations.response.share_issue"))?;
    let target = exact
        .values()
        .chain(path_resources)
        .find(|operation| operation.policy.operation_id() == rule.target_operation_id())
        .ok_or(ConfigError::Invalid("operations.response.share_issue"))?;
    if target.policy.admission_class() != AdmissionClass::ShareEntry
        || target.method != HttpMethod::Get
        || target.policy.operation_id() == source.policy.operation_id()
        || !target.resource.as_ref().is_some_and(|resource| {
            resource.resource_type == source_resource.resource_type
                && matches!(resource.location, CompiledResourceLocation::Query(_))
        })
    {
        return Err(ConfigError::Invalid("operations.response.share_issue"));
    }
    Ok(())
}

/// Trusted resource semantics compiled for one matched operation.
#[derive(Clone, Copy, Debug)]
pub struct ResourceOperation<'a> {
    /// Exact operation selected by method and path.
    pub operation_id: &'a OperationId,
    /// Canonical resource type used in action and grant checks.
    pub resource_type: &'a ResourceType,
    /// Exact view required by the resource grant.
    pub view_profile: &'a ViewProfile,
    /// Versioned location containing the canonical resource reference.
    pub location: ResourceLocation<'a>,
}

/// Trusted resource-reference location compiled from one operation.
#[derive(Clone, Copy, Debug)]
pub enum ResourceLocation<'a> {
    /// One strict query parameter on an exact path.
    Query(&'a FieldName),
    /// One strict final path segment following a fixed prefix.
    FinalPathSegment {
        /// Fixed raw path prefix ending in `/`.
        prefix: &'a str,
        /// Field identity used by the action field policy.
        parameter: &'a FieldName,
    },
}

/// Complete-buffer response behavior selected by trusted operation configuration.
#[derive(Clone, Copy)]
pub enum BufferedResponsePolicy<'a> {
    /// Strict JSON validation and optional response-side qualification.
    Json {
        /// Maximum complete entity size.
        max_bytes: usize,
    },
    /// Exact-build HTML sensor injection.
    SensorHtml(&'a sensor_html::SensorHtmlRule),
}

impl BufferedResponsePolicy<'_> {
    /// Returns the maximum accepted source entity size.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::Json { max_bytes } => max_bytes,
            Self::SensorHtml(rule) => rule.max_bytes(),
        }
    }

    /// Returns the conservative source/rewrite memory reservation.
    #[must_use]
    pub fn max_in_flight_bytes(self) -> Option<usize> {
        match self {
            Self::Json { max_bytes } => max_bytes.checked_mul(2),
            Self::SensorHtml(rule) => rule.max_in_flight_bytes(),
        }
    }
}

/// Approved response extraction rule resolved to one exact UI resource operation.
#[derive(Clone, Copy, Debug)]
pub struct ResponseGrantOperation<'a> {
    /// Strict JSON extraction and issuance limits.
    pub rule: &'a ResponseGrantRule,
    /// Descriptor that creates the target action grant.
    pub target_action_id: &'a ActionId,
    /// Exact versioned action mapping selected by trusted configuration.
    pub target_mapping_revision: &'a MappingRevision,
    /// Canonical resource type shared by action and resource grants.
    pub resource_type: &'a ResourceType,
    /// Exact view shared by action and resource grants.
    pub view_profile: &'a ViewProfile,
    /// Request field authorized by the generated target action.
    pub target_field: &'a FieldName,
}

/// Exact source and read-only target selected by a trusted share response rule.
#[derive(Clone, Copy, Debug)]
pub struct ResponseShareOperation<'a> {
    /// Complete-response validation and independently approved issuance rule.
    pub rule: &'a ResponseShareRule,
    /// Dedicated issuer operation used by the request's exact resource grant.
    pub source_operation_id: &'a OperationId,
    /// Issuer view that the independent rule must approve.
    pub source_view_profile: &'a ViewProfile,
    /// Canonical resource type shared by source and target operations.
    pub resource_type: &'a ResourceType,
    /// Limited response view exposed at the fixed share entry.
    pub view_profile: &'a ViewProfile,
}

impl IdentityStoreConfig {
    /// Returns the maximum number of `PostgreSQL` connections.
    #[must_use]
    pub const fn max_connections(self) -> u32 {
        self.max_connections
    }

    /// Returns the bounded pool acquisition timeout in milliseconds.
    #[must_use]
    pub const fn acquire_timeout_ms(self) -> u64 {
        self.acquire_timeout_ms
    }

    /// Returns the server-side anonymous-session lease in seconds.
    #[must_use]
    pub const fn anonymous_session_ttl_seconds(self) -> u64 {
        self.anonymous_session_ttl_seconds
    }

    /// Returns the active anonymous-session bound per tenant and site.
    #[must_use]
    pub const fn max_active_anonymous_sessions(self) -> u32 {
        self.max_active_anonymous_sessions
    }

    /// Returns the anonymous-session creation-rate window in seconds.
    #[must_use]
    pub const fn anonymous_session_rate_window_seconds(self) -> u64 {
        self.anonymous_session_rate_window_seconds
    }

    /// Returns the creation bound for one normalized client source.
    #[must_use]
    pub const fn max_anonymous_session_creations_per_source(self) -> u32 {
        self.max_anonymous_session_creations_per_source
    }

    /// Returns the creation bound for this tenant and site.
    #[must_use]
    pub const fn max_anonymous_session_creations_per_site(self) -> u32 {
        self.max_anonymous_session_creations_per_site
    }
}

impl SensorConfig {
    /// Returns the exact browser origin permitted to submit observations.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns the server-approved page build fingerprint exposed to the sensor.
    #[must_use]
    pub fn build_ref(&self) -> &str {
        &self.build_ref
    }

    /// Returns the configured active-page heartbeat interval.
    #[must_use]
    pub const fn heartbeat_seconds(&self) -> u16 {
        self.heartbeat_seconds
    }
}

fn validate_sensor(sensor: SensorDto) -> Result<SensorConfig, ConfigError> {
    BuildFingerprint::parse(&sensor.build_ref).map_err(ConfigError::Provenance)?;
    if !(5..=300).contains(&sensor.heartbeat_seconds) {
        return Err(ConfigError::Invalid("sensor.heartbeat_seconds"));
    }
    let uri =
        http::Uri::from_str(&sensor.origin).map_err(|_| ConfigError::Invalid("sensor.origin"))?;
    let scheme = uri
        .scheme_str()
        .ok_or(ConfigError::Invalid("sensor.origin"))?;
    let authority = uri
        .authority()
        .ok_or(ConfigError::Invalid("sensor.origin"))?;
    let canonical = format!("{scheme}://{authority}");
    let loopback = matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]");
    if sensor.origin != canonical || (scheme != "https" && !(scheme == "http" && loopback)) {
        return Err(ConfigError::Invalid("sensor.origin"));
    }
    Ok(SensorConfig {
        origin: sensor.origin,
        build_ref: sensor.build_ref,
        heartbeat_seconds: sensor.heartbeat_seconds,
    })
}

fn compile_operation(dto: OperationDto) -> Result<CompiledOperation, ConfigError> {
    let method = parse_method(&dto.method).ok_or(ConfigError::Invalid("operations.method"))?;
    if dto.path.starts_with(INTERNAL_PATH_PREFIX)
        || dto.path.contains(['{', '}']) && dto.resource_path_parameter.is_none()
    {
        return Err(ConfigError::Invalid("operations.path"));
    }
    let route = RouteTemplate::parse(dto.path.clone()).map_err(ConfigError::Provenance)?;
    let source_action = dto
        .source_action
        .map(ActionId::parse)
        .transpose()
        .map_err(ConfigError::Domain)?;
    let (capability, resource, route_match) = match (
        dto.resource_type,
        dto.view_profile,
        dto.resource_query_parameter,
        dto.resource_path_parameter,
    ) {
        (None, None, None, None) if !dto.path.contains(['{', '}']) => (
            CapabilityPolicy::None,
            None,
            CompiledRouteMatch::Exact(dto.path.clone()),
        ),
        (Some(resource_type), Some(view_profile), Some(query_parameter), None)
            if method == HttpMethod::Get =>
        {
            let resource_type = ResourceType::parse(resource_type).map_err(ConfigError::Domain)?;
            let view_profile = ViewProfile::parse(view_profile).map_err(ConfigError::Domain)?;
            let query_parameter = FieldName::parse(query_parameter).map_err(ConfigError::Domain)?;
            (
                CapabilityPolicy::ExactResource {
                    resource_type: resource_type.clone(),
                    view_profile: view_profile.clone(),
                },
                Some(CompiledResource {
                    resource_type,
                    view_profile,
                    location: CompiledResourceLocation::Query(query_parameter),
                }),
                CompiledRouteMatch::Exact(dto.path.clone()),
            )
        }
        (Some(resource_type), Some(view_profile), None, Some(path_parameter))
            if method == HttpMethod::Get =>
        {
            let resource_type = ResourceType::parse(resource_type).map_err(ConfigError::Domain)?;
            let view_profile = ViewProfile::parse(view_profile).map_err(ConfigError::Domain)?;
            let parameter = FieldName::parse(path_parameter).map_err(ConfigError::Domain)?;
            let prefix = final_resource_prefix(&dto.path, &parameter)?;
            (
                CapabilityPolicy::ExactResource {
                    resource_type: resource_type.clone(),
                    view_profile: view_profile.clone(),
                },
                Some(CompiledResource {
                    resource_type,
                    view_profile,
                    location: CompiledResourceLocation::FinalPathSegment {
                        prefix: prefix.clone(),
                        parameter,
                    },
                }),
                CompiledRouteMatch::FinalResourceSegment { prefix },
            )
        }
        _ => return Err(ConfigError::Invalid("operation capability")),
    };
    let policy = OperationPolicy::new(
        OperationId::parse(dto.operation_id).map_err(ConfigError::Domain)?,
        method,
        route.clone(),
        dto.admission.into(),
        source_action.clone(),
        capability,
    )
    .map_err(ConfigError::Policy)?;
    let response = compile_optional_response(dto.response, method)?;
    let response_has_side_effects = response
        .as_ref()
        .is_some_and(CompiledResponse::has_side_effects);
    let request_crypto = dto
        .request_crypto
        .map(|rule| compile_request_crypto(rule, method, dto.admission, response_has_side_effects))
        .transpose()?;
    Ok(CompiledOperation {
        method,
        route,
        route_match,
        policy,
        source_action,
        resource,
        request_crypto,
        issued_by: dto
            .issued_by
            .map(page_actions::compile_issued_by)
            .transpose()?,
        response,
    })
}

fn compile_request_crypto(
    dto: RequestCryptoDto,
    method: HttpMethod,
    admission: AdmissionDto,
    response_has_side_effects: bool,
) -> Result<RequestCryptoPolicy, ConfigError> {
    if !matches!(
        method,
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
    ) {
        return Err(ConfigError::Invalid("operations.request_crypto"));
    }
    match dto {
        RequestCryptoDto::Observe { adapter_revision } => {
            if matches!(admission, AdmissionDto::UiActionRequired)
                || response_has_side_effects
                || !valid_scoped_value(&adapter_revision)
            {
                return Err(ConfigError::Invalid("operations.request_crypto"));
            }
            Ok(RequestCryptoPolicy::Observe(RequestCryptoObserveRule {
                adapter_revision,
            }))
        }
        RequestCryptoDto::Compatibility {
            adapter_revision,
            approval_ref,
            expires_at,
            build_fingerprints,
        } => {
            let unique_builds = build_fingerprints.iter().collect::<BTreeSet<_>>();
            if !matches!(admission, AdmissionDto::UiActionRequired)
                || response_has_side_effects
                || !valid_scoped_value(&adapter_revision)
                || !valid_scoped_value(&approval_ref)
                || expires_at == 0
                || !(1..=16).contains(&build_fingerprints.len())
                || unique_builds.len() != build_fingerprints.len()
            {
                return Err(ConfigError::Invalid("operations.request_crypto"));
            }
            let build_fingerprints = build_fingerprints
                .iter()
                .map(|value| {
                    xshield_core::provenance::BuildFingerprint::parse(value)
                        .map_err(ConfigError::Provenance)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RequestCryptoPolicy::Compatibility(
                request_crypto::RequestCryptoCompatibilityRule {
                    adapter_revision,
                    approval_ref,
                    expires_at: UnixSeconds::new(expires_at),
                    build_fingerprints,
                },
            ))
        }
        RequestCryptoDto::DirectDecrypt {
            adapter_revision,
            key_id,
            key_not_before,
            key_expires_at,
            max_envelope_bytes,
            max_plaintext_bytes,
            max_message_age_seconds,
            max_future_skew_seconds,
            max_active_messages,
        } => {
            if matches!(admission, AdmissionDto::UiActionRequired)
                || !valid_scoped_value(&adapter_revision)
                || !valid_scoped_value(&key_id)
                || key_not_before >= key_expires_at
                || !(1..=MAX_ENCRYPTED_REQUEST_ENVELOPE_BYTES).contains(&max_envelope_bytes)
                || max_plaintext_bytes == 0
                || max_plaintext_bytes > max_envelope_bytes / 2
                || !(1..=3_600).contains(&max_message_age_seconds)
                || max_future_skew_seconds > 300
                || !(1..=1_000_000).contains(&max_active_messages)
            {
                return Err(ConfigError::Invalid("operations.request_crypto"));
            }
            Ok(RequestCryptoPolicy::Enforce(RequestCryptoRule {
                adapter_revision,
                key_id,
                key_not_before: UnixSeconds::new(key_not_before),
                key_expires_at: UnixSeconds::new(key_expires_at),
                max_envelope_bytes,
                max_plaintext_bytes,
                max_message_age_seconds,
                max_future_skew_seconds,
                max_active_messages,
                // 3E covers read overlap and the later envelope/tree/ciphertext/
                // plaintext peaks because validated plaintext is at most E/2.
                max_in_flight_bytes: max_envelope_bytes
                    .checked_mul(3)
                    .and_then(|bytes| bytes.checked_add(REQUEST_CRYPTO_FIXED_IN_FLIGHT_BYTES))
                    .filter(|bytes| *bytes <= MAX_BUFFERED_BODY_IN_FLIGHT_BYTES)
                    .ok_or(ConfigError::Invalid("operations.request_crypto"))?,
            }))
        }
    }
}

fn compile_optional_response(
    dto: Option<ResponseDto>,
    method: HttpMethod,
) -> Result<Option<CompiledResponse>, ConfigError> {
    dto.map(|response| compile_response(response, method))
        .transpose()
}

#[allow(clippy::too_many_lines)]
fn compile_response(
    mut dto: ResponseDto,
    method: HttpMethod,
) -> Result<CompiledResponse, ConfigError> {
    if !(1..=MAX_BUFFERED_JSON_BYTES).contains(&dto.max_bytes) {
        return Err(ConfigError::Invalid("operations.response.max_bytes"));
    }
    let kind = compile_response_kind(&mut dto, method)?;
    let page_actions = dto
        .page_actions
        .take()
        .map(page_actions::compile_page_actions)
        .transpose()?;
    let crypto = dto
        .crypto
        .map(|crypto| compile_response_crypto(crypto, dto.max_bytes))
        .transpose()?;
    let grant = dto
        .resource_grant
        .map(|grant| {
            if !(200..=299).contains(&grant.success_status)
                || grant.success_status == 204
                || !valid_json_pointer(&grant.items_pointer)
                || !valid_json_pointer(&grant.resource_pointer)
                || !(1..=1_000).contains(&grant.max_items)
                || !(1..=5_000).contains(&grant.max_active_grants)
                || !(1..=86_400).contains(&grant.ttl_seconds)
            {
                return Err(ConfigError::Invalid("operations.response.resource_grant"));
            }
            Ok(ResponseGrantRule {
                success_status: grant.success_status,
                items_pointer: grant.items_pointer,
                resource_pointer: grant.resource_pointer,
                action_ref_field: FieldName::parse(grant.action_ref_field)
                    .map_err(ConfigError::Domain)?,
                target_operation_id: OperationId::parse(grant.target_operation_id)
                    .map_err(ConfigError::Domain)?,
                target_mapping_revision: MappingRevision::parse(grant.target_mapping_revision)
                    .map_err(ConfigError::Domain)?,
                ttl_seconds: grant.ttl_seconds,
                max_items: grant.max_items,
                max_active_grants: grant.max_active_grants,
            })
        })
        .transpose()?;
    let auth_binding = dto
        .auth_binding
        .map(|binding| {
            if !(200..=299).contains(&binding.success_status)
                || binding.success_status == 204
                || !valid_auth_pointers(
                    &binding.principal_pointer,
                    &binding.authorization_context_pointer,
                    &binding.bearer_pointer,
                )
                || !(1..=86_400).contains(&binding.credential_ttl_seconds)
                || !(1..=86_400).contains(&binding.session_ttl_seconds)
                || binding.credential_ttl_seconds > binding.session_ttl_seconds
            {
                return Err(ConfigError::Invalid("operations.response.auth_binding"));
            }
            Ok(AuthBindingRule {
                success_status: binding.success_status,
                principal_pointer: binding.principal_pointer,
                authorization_context_pointer: binding.authorization_context_pointer,
                bearer_pointer: binding.bearer_pointer,
                credential_ttl_seconds: binding.credential_ttl_seconds,
                session_ttl_seconds: binding.session_ttl_seconds,
            })
        })
        .transpose()?;
    let auth_revoke = dto
        .auth_revoke
        .map(|revoke| {
            if !(200..=299).contains(&revoke.success_status)
                || matches!(revoke.success_status, 204..=206)
            {
                return Err(ConfigError::Invalid("operations.response.auth_revoke"));
            }
            Ok(AuthRevokeRule {
                success_status: revoke.success_status,
            })
        })
        .transpose()?;
    let share_issue = dto
        .share_issue
        .map(|share| {
            if !(200..=299).contains(&share.success_status)
                || matches!(share.success_status, 204..=206)
                || !(1..=86_400).contains(&share.ttl_seconds)
                || !(1..=5_000).contains(&share.max_active_shares)
            {
                return Err(ConfigError::Invalid("operations.response.share_issue"));
            }
            Ok(ResponseShareRule {
                success_status: share.success_status,
                token_field: FieldName::parse(share.token_field).map_err(ConfigError::Domain)?,
                target_operation_id: OperationId::parse(share.target_operation_id)
                    .map_err(ConfigError::Domain)?,
                issuance_rule_id: ShareIssuanceRuleId::parse(share.issuance_rule_id)
                    .map_err(ConfigError::Domain)?,
                ttl_seconds: share.ttl_seconds,
                max_active_shares: share.max_active_shares,
            })
        })
        .transpose()?;
    let auth_refresh =
        compile_auth_transition(dto.auth_refresh, "operations.response.auth_refresh")?;
    let auth_context_switch = compile_auth_transition(
        dto.auth_context_switch,
        "operations.response.auth_context_switch",
    )?;
    // Share secrets stay in the fixed release buffer; the encryption adapter's
    // JSON tree currently copies strings into ordinary, non-erasing allocations.
    if share_issue.is_some() && crypto.is_some() {
        return Err(ConfigError::Invalid("operations.response.share_issue"));
    }
    if usize::from(grant.is_some())
        + usize::from(share_issue.is_some())
        + usize::from(auth_binding.is_some())
        + usize::from(auth_revoke.is_some())
        + usize::from(auth_refresh.is_some())
        + usize::from(auth_context_switch.is_some())
        > 1
    {
        return Err(ConfigError::Invalid("operations.response"));
    }
    let bearer_pointer = auth_binding
        .as_ref()
        .map(|rule| rule.bearer_pointer.as_str())
        .or_else(|| {
            auth_refresh
                .as_ref()
                .map(|rule| rule.bearer_pointer.as_str())
        })
        .or_else(|| {
            auth_context_switch
                .as_ref()
                .map(|rule| rule.bearer_pointer.as_str())
        });
    let evidence_capture = dto
        .evidence_capture
        .map(|capture| {
            if capture.max_bytes > dto.max_bytes {
                return Err(ConfigError::Invalid(
                    "operations.response.evidence_capture.max_bytes",
                ));
            }
            EvidenceCaptureRule::compile(capture, bearer_pointer)
        })
        .transpose()?;
    Ok(CompiledResponse {
        kind,
        page_actions,
        max_bytes: dto.max_bytes,
        crypto,
        grant,
        share_issue,
        auth_binding,
        auth_revoke,
        auth_refresh,
        auth_context_switch,
        evidence_capture,
    })
}

fn compile_response_kind(
    dto: &mut ResponseDto,
    method: HttpMethod,
) -> Result<ResponseKind, ConfigError> {
    match dto.mode {
        ResponseModeDto::BufferedJson => {
            if dto.adapter_revision.is_some()
                || dto.origin_sha256.is_some()
                || dto.injection_offset.is_some()
                || !dto.additional_adapters.is_empty()
                || dto.page_actions.is_some()
            {
                return Err(ConfigError::Invalid("operations.response"));
            }
            Ok(ResponseKind::BufferedJson)
        }
        ResponseModeDto::SensorHtml => {
            if method != HttpMethod::Get
                || dto.crypto.is_some()
                || dto.resource_grant.is_some()
                || dto.share_issue.is_some()
                || dto.auth_binding.is_some()
                || dto.auth_revoke.is_some()
                || dto.auth_refresh.is_some()
                || dto.auth_context_switch.is_some()
                || dto.evidence_capture.is_some()
            {
                return Err(ConfigError::Invalid("operations.response"));
            }
            let adapter_revision = dto
                .adapter_revision
                .take()
                .filter(|value| valid_scoped_value(value))
                .ok_or(ConfigError::Invalid("operations.response.adapter_revision"))?;
            let origin_sha256 = dto
                .origin_sha256
                .take()
                .ok_or(ConfigError::Invalid("operations.response.origin_sha256"))?;
            BuildFingerprint::parse(&origin_sha256).map_err(ConfigError::Provenance)?;
            let injection_offset = dto
                .injection_offset
                .take()
                .filter(|offset| *offset < dto.max_bytes)
                .ok_or(ConfigError::Invalid("operations.response.injection_offset"))?;
            if dto.additional_adapters.len() > 15 {
                return Err(ConfigError::Invalid(
                    "operations.response.additional_adapters",
                ));
            }
            let mut adapters = vec![(adapter_revision, origin_sha256, injection_offset)];
            for adapter in std::mem::take(&mut dto.additional_adapters) {
                if !valid_scoped_value(&adapter.adapter_revision)
                    || BuildFingerprint::parse(&adapter.origin_sha256).is_err()
                    || adapter.injection_offset >= dto.max_bytes
                {
                    return Err(ConfigError::Invalid(
                        "operations.response.additional_adapters",
                    ));
                }
                adapters.push((
                    adapter.adapter_revision,
                    adapter.origin_sha256,
                    adapter.injection_offset,
                ));
            }
            let unique_revisions = adapters
                .iter()
                .map(|(revision, _, _)| revision)
                .collect::<BTreeSet<_>>();
            let unique_digests = adapters
                .iter()
                .map(|(_, digest, _)| digest)
                .collect::<BTreeSet<_>>();
            if unique_revisions.len() != adapters.len() || unique_digests.len() != adapters.len() {
                return Err(ConfigError::Invalid(
                    "operations.response.additional_adapters",
                ));
            }
            Ok(ResponseKind::SensorHtml(sensor_html::SensorHtmlRule::new(
                dto.max_bytes,
                adapters,
            )))
        }
    }
}

fn compile_response_crypto(
    crypto: ResponseCryptoDto,
    max_plaintext_bytes: usize,
) -> Result<ResponseCryptoRule, ConfigError> {
    let minimum_envelope_bytes = max_plaintext_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1024))
        .ok_or(ConfigError::Invalid("operations.response.crypto"))?;
    if !matches!(crypto.mode, ResponseCryptoModeDto::DirectEncrypt)
        || !valid_scoped_value(&crypto.adapter_revision)
        || !valid_scoped_value(&crypto.key_id)
        || crypto.key_not_before >= crypto.key_expires_at
        || !(1..=3_600).contains(&crypto.message_ttl_seconds)
        || crypto.max_envelope_bytes < minimum_envelope_bytes
        || crypto.max_envelope_bytes > MAX_ENCRYPTED_RESPONSE_ENVELOPE_BYTES
    {
        return Err(ConfigError::Invalid("operations.response.crypto"));
    }
    Ok(ResponseCryptoRule {
        adapter_revision: crypto.adapter_revision,
        key_id: crypto.key_id,
        key_not_before: UnixSeconds::new(crypto.key_not_before),
        key_expires_at: UnixSeconds::new(crypto.key_expires_at),
        message_ttl_seconds: crypto.message_ttl_seconds,
        max_envelope_bytes: crypto.max_envelope_bytes,
        max_in_flight_bytes: max_plaintext_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(crypto.max_envelope_bytes))
            .and_then(|bytes| bytes.checked_add(RESPONSE_CRYPTO_FIXED_IN_FLIGHT_BYTES))
            .filter(|bytes| *bytes <= MAX_BUFFERED_BODY_IN_FLIGHT_BYTES)
            .ok_or(ConfigError::Invalid("operations.response.crypto"))?,
    })
}

fn compile_auth_transition(
    transition: Option<AuthRefreshDto>,
    field: &'static str,
) -> Result<Option<AuthTransitionRule>, ConfigError> {
    transition
        .map(|transition| {
            if !(200..=299).contains(&transition.success_status)
                || transition.success_status == 204
                || !valid_auth_pointers(
                    &transition.principal_pointer,
                    &transition.authorization_context_pointer,
                    &transition.bearer_pointer,
                )
                || !(1..=86_400).contains(&transition.credential_ttl_seconds)
            {
                return Err(ConfigError::Invalid(field));
            }
            Ok(AuthTransitionRule {
                success_status: transition.success_status,
                principal_pointer: transition.principal_pointer,
                authorization_context_pointer: transition.authorization_context_pointer,
                bearer_pointer: transition.bearer_pointer,
                credential_ttl_seconds: transition.credential_ttl_seconds,
            })
        })
        .transpose()
}

fn valid_auth_pointers(principal: &str, context: &str, bearer: &str) -> bool {
    valid_json_pointer(principal)
        && valid_json_pointer(context)
        && valid_json_pointer(bearer)
        && principal != context
        && principal != bearer
        && context != bearer
}

fn valid_json_pointer(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 512
        && value.bytes().all(|byte| !byte.is_ascii_control())
        && value
            .as_bytes()
            .windows(2)
            .filter(|pair| pair[0] == b'~')
            .all(|pair| matches!(pair[1], b'0' | b'1'))
        && value.as_bytes().last().is_none_or(|byte| *byte != b'~')
}

impl CompiledResponse {
    /// Whether releasing this response encrypts, issues, or changes identity.
    const fn has_side_effects(&self) -> bool {
        self.crypto.is_some()
            || self.grant.is_some()
            || self.share_issue.is_some()
            || self.auth_binding.is_some()
            || self.auth_revoke.is_some()
            || self.auth_refresh.is_some()
            || self.auth_context_switch.is_some()
    }
}

impl CompiledOperation {
    fn matches_text(&self, method: &str, path: &str) -> bool {
        self.method.as_str() == method && self.matches(self.method, path)
    }

    fn matches(&self, method: HttpMethod, path: &str) -> bool {
        if self.method != method {
            return false;
        }
        match &self.route_match {
            CompiledRouteMatch::Exact(expected) => expected == path,
            CompiledRouteMatch::FinalResourceSegment { prefix } => path
                .strip_prefix(prefix)
                .is_some_and(|segment| !segment.is_empty() && !segment.contains('/')),
        }
    }
}

fn final_resource_prefix(path: &str, parameter: &FieldName) -> Result<String, ConfigError> {
    let marker = format!("{{{}}}", parameter.as_str());
    let Some(prefix) = path.strip_suffix(&marker) else {
        return Err(ConfigError::Invalid("operations.path"));
    };
    if !prefix.ends_with('/')
        || prefix.contains(['{', '}', '%'])
        || prefix.contains("//")
        || prefix
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(ConfigError::Invalid("operations.path"));
    }
    Ok(prefix.to_owned())
}

fn parse_method(value: &str) -> Option<HttpMethod> {
    match value {
        "GET" => Some(HttpMethod::Get),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "PATCH" => Some(HttpMethod::Patch),
        "DELETE" => Some(HttpMethod::Delete),
        _ => None,
    }
}

fn valid_server_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_scoped_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn validate_audit_directory(value: String) -> Result<PathBuf, ConfigError> {
    if value.is_empty() || value.len() > 1024 || value.as_bytes().contains(&0) {
        return Err(ConfigError::Invalid("audit.directory"));
    }
    let path = PathBuf::from(value);
    let mut has_normal_component = false;
    if path.components().any(|component| match component {
        Component::ParentDir => true,
        Component::Normal(_) => {
            has_normal_component = true;
            false
        }
        _ => false,
    }) || !has_normal_component
    {
        return Err(ConfigError::Invalid("audit.directory"));
    }
    Ok(path)
}

impl From<AdmissionDto> for AdmissionClass {
    fn from(value: AdmissionDto) -> Self {
        match value {
            AdmissionDto::Public => Self::Public,
            AdmissionDto::AuthenticationEntry => Self::AuthenticationEntry,
            AdmissionDto::AuthenticatedRoot => Self::AuthenticatedRoot,
            AdmissionDto::UiActionRequired => Self::UiActionRequired,
            AdmissionDto::ShareEntry => Self::ShareEntry,
            AdmissionDto::ServiceIdentity => Self::ServiceIdentity,
        }
    }
}

/// Admission outcome exposed to the network and audit adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayOutcome {
    /// The exact route may proceed to the durability barrier.
    Allowed,
    /// The request must terminate before origin dispatch.
    Denied,
}

/// Terminal deterministic admission result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDecision {
    /// Allow or deny result.
    pub outcome: GatewayOutcome,
    /// Exact configured operation, or `None` when routing did not match.
    pub operation_id: Option<OperationId>,
    /// Stable machine-readable decision reason.
    pub reason_code: ReasonCode,
}

/// Startup configuration rejection.
#[derive(Debug)]
pub enum ConfigError {
    /// JSON syntax or shape is invalid.
    Json(serde_json::Error),
    /// A named network or cross-field value is invalid.
    Invalid(&'static str),
    /// A domain identifier is invalid.
    Domain(xshield_core::domain::InvalidValue),
    /// An action route is invalid.
    Provenance(xshield_core::provenance::ProvenanceError),
    /// Admission fields form an incoherent policy.
    Policy(xshield_core::admission::OperationPolicyError),
    /// Journal capacity settings are incoherent.
    Journal(xshield_audit::JournalError),
    /// Two operations claim the same method and exact path.
    DuplicateRoute,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(_) => formatter.write_str("invalid gateway JSON"),
            Self::Invalid(field) => write!(formatter, "invalid {field}"),
            Self::Domain(error) => error.fmt(formatter),
            Self::Provenance(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::Journal(error) => error.fmt(formatter),
            Self::DuplicateRoute => formatter.write_str("duplicate operation method and path"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Domain(error) => Some(error),
            Self::Provenance(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::Journal(error) => Some(error),
            Self::Invalid(_) | Self::DuplicateRoute => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{
      "listen":"127.0.0.1:6188",
      "origin":{"address":"127.0.0.1:8080","server_name":"origin.example","tls":false},
      "tenant_id":"tenant_demo",
      "site_id":"site_demo",
      "policy_revision":"policy-r1",
      "audit":{"directory":"target/xshield-audit-test","key_id":"journal-key-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
      "identity_store":{"max_connections":4,"acquire_timeout_ms":1000},
      "sensor":{"origin":"https://app.example","build_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","heartbeat_seconds":15},
      "operations":[
        {"operation_id":"catalog.read","method":"GET","path":"/catalog","admission":"PUBLIC","source_action":null,"resource_type":null,"view_profile":null},
        {"operation_id":"account.update","method":"POST","path":"/account","admission":"UI_ACTION_REQUIRED","source_action":"account_form.submit","resource_type":null,"view_profile":null}
      ]
    }"#;

    #[test]
    fn admits_only_exact_unprotected_routes() {
        let config = GatewayConfig::from_json(CONFIG.as_bytes()).unwrap();
        let public = config.admit("GET", "/catalog", UnixSeconds::new(1));
        assert_eq!(public.outcome, GatewayOutcome::Allowed);
        assert_eq!(public.reason_code, ReasonCode::PublicEntryAllowed);
        assert_eq!(public.operation_id.unwrap().as_str(), "catalog.read");
        let protected = config.admit("POST", "/account", UnixSeconds::new(1));
        assert_eq!(protected.outcome, GatewayOutcome::Denied);
        assert_eq!(protected.reason_code, ReasonCode::UiActionNotAvailable);
        let unknown = config.admit("GET", "/catalog/1", UnixSeconds::new(1));
        assert_eq!(unknown.outcome, GatewayOutcome::Denied);
        assert_eq!(unknown.reason_code, ReasonCode::OperationNotMatched);
        assert!(unknown.operation_id.is_none());
        let sensor = config.admit("GET", SENSOR_ASSET_PATH, UnixSeconds::new(1));
        assert_eq!(sensor.outcome, GatewayOutcome::Allowed);
        assert_eq!(sensor.reason_code, ReasonCode::PublicEntryAllowed);
        assert_eq!(
            sensor.operation_id.unwrap().as_str(),
            SENSOR_ASSET_OPERATION_ID
        );
        assert_eq!(
            config.internal_response("GET", SENSOR_ASSET_PATH),
            Some(InternalResponse::SensorAsset)
        );
        assert_eq!(
            config.internal_response("GET", SENSOR_LOADER_PATH),
            Some(InternalResponse::SensorLoader)
        );
        assert!(
            config
                .internal_response("POST", SENSOR_ASSET_PATH)
                .is_none()
        );
        let bootstrap = config.admit("GET", SENSOR_BOOTSTRAP_PATH, UnixSeconds::new(1));
        assert_eq!(bootstrap.outcome, GatewayOutcome::Allowed);
        assert_eq!(
            bootstrap.operation_id.unwrap().as_str(),
            SENSOR_BOOTSTRAP_OPERATION_ID
        );
        assert_eq!(
            config.internal_response("GET", SENSOR_BOOTSTRAP_PATH),
            Some(InternalResponse::SensorBootstrap)
        );
        let sensor = config.sensor().unwrap();
        assert_eq!(sensor.heartbeat_seconds(), 15);
        assert_eq!(sensor.build_ref().len(), 64);
        assert!(
            config
                .internal_response("POST", SENSOR_BOOTSTRAP_PATH)
                .is_none()
        );
        let prepare = config.admit("POST", SENSOR_PREPARE_PATH, UnixSeconds::new(1));
        assert_eq!(prepare.outcome, GatewayOutcome::Denied);
        assert_eq!(prepare.reason_code, ReasonCode::AuthRequired);
        let prepare = config.admit_sensor_session("POST", SENSOR_PREPARE_PATH);
        assert_eq!(prepare.outcome, GatewayOutcome::Allowed);
        assert_eq!(prepare.reason_code, ReasonCode::SensorObservationAccepted);
    }

    #[test]
    fn static_asset_fallback_is_opt_in_and_never_admits_api_paths() {
        let denied = |config: &GatewayConfig, path: &str| {
            let decision = config.admit("GET", path, UnixSeconds::new(1));
            assert_eq!(decision.outcome, GatewayOutcome::Denied, "{path}");
            assert_eq!(
                decision.reason_code,
                ReasonCode::OperationNotMatched,
                "{path}"
            );
            assert!(decision.operation_id.is_none(), "{path}");
        };
        // No site policy, an empty one, and an explicit zero all leave it off.
        for policy in [
            None,
            Some(r#""site_policy":{},"#),
            Some(r#""site_policy":{"static_asset_max_path_depth":0},"#),
        ] {
            let configured = match policy {
                Some(policy) => {
                    CONFIG.replace("\"operations\":[", &format!("{policy}\"operations\":["))
                }
                None => CONFIG.to_owned(),
            };
            let config = GatewayConfig::from_json(configured.as_bytes()).unwrap();
            denied(&config, "/assets/app.js");
            denied(&config, "/styles.css");
        }
        let opted_in = CONFIG.replace(
            "\"operations\":[",
            "\"site_policy\":{\"static_asset_max_path_depth\":5},\"operations\":[",
        );
        let config = GatewayConfig::from_json(opted_in.as_bytes()).unwrap();
        let asset = config.admit("GET", "/assets/app.js", UnixSeconds::new(1));
        assert_eq!(asset.outcome, GatewayOutcome::Allowed);
        assert_eq!(asset.reason_code, ReasonCode::PublicEntryAllowed);
        assert_eq!(
            asset.operation_id.unwrap().as_str(),
            STATIC_ASSET_OPERATION_ID
        );
        // The reviewer's paths: APIs spelled as assets and origin path tricks.
        for path in [
            "/orders/123.json",
            "/api/v1/users/42.json",
            "/admin/export.json",
            "/assets/app.js.map",
            "/api/json",
            "/api/v1/map",
            "/css",
            "/search/png",
            "/admin/users;.js",
            "/admin/dashboard;.css",
            "/api/accounts/..;/x.js",
            "/admin/users%3b.js",
            "/a/%2e%2e/admin.js",
            "/a%2fb.js",
            "/api/users",
        ] {
            denied(&config, path);
        }
        // Only GET is a static asset, and exact operations are unaffected.
        let post = config.admit("POST", "/assets/app.js", UnixSeconds::new(1));
        assert_eq!(post.outcome, GatewayOutcome::Denied);
        let exact = config.admit("GET", "/catalog", UnixSeconds::new(1));
        assert_eq!(exact.operation_id.unwrap().as_str(), "catalog.read");
    }

    #[test]
    fn compiles_exact_sensor_html_response_adapter() {
        let configured = CONFIG.replace(
            "{\"operation_id\":\"catalog.read\",\"method\":\"GET\",\"path\":\"/catalog\",\"admission\":\"PUBLIC\",\"source_action\":null,\"resource_type\":null,\"view_profile\":null}",
            "{\"operation_id\":\"catalog.read\",\"method\":\"GET\",\"path\":\"/catalog\",\"admission\":\"PUBLIC\",\"source_action\":null,\"resource_type\":null,\"view_profile\":null,\"response\":{\"mode\":\"SENSOR_HTML\",\"max_bytes\":128,\"adapter_revision\":\"home-r1\",\"origin_sha256\":\"8afe2e0204ebb1d838fdd6ce33cfb526ad18ca0d3877cc1a3768a778332c054a\",\"injection_offset\":27,\"additional_adapters\":[{\"adapter_revision\":\"home-r2\",\"origin_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"injection_offset\":21}]}}",
        );
        let config = GatewayConfig::from_json(configured.as_bytes()).unwrap();
        assert!(matches!(
            config.buffered_response_policy("GET", "/catalog"),
            Some(BufferedResponsePolicy::SensorHtml(rule))
                if rule.max_bytes() == 128
        ));

        let duplicate_digest = configured.replace(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "8afe2e0204ebb1d838fdd6ce33cfb526ad18ca0d3877cc1a3768a778332c054a",
        );
        assert!(matches!(
            GatewayConfig::from_json(duplicate_digest.as_bytes()),
            Err(ConfigError::Invalid(
                "operations.response.additional_adapters"
            ))
        ));

        let missing_sensor = configured.replace(
            "      \"sensor\":{\"origin\":\"https://app.example\",\"build_ref\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"heartbeat_seconds\":15},\n",
            "",
        );
        assert!(matches!(
            GatewayConfig::from_json(missing_sensor.as_bytes()),
            Err(ConfigError::Invalid("sensor"))
        ));
    }

    #[test]
    fn rejects_ambiguous_or_template_routes() {
        let duplicate = CONFIG.replace(
            "\"method\":\"POST\",\"path\":\"/account\",\"admission\":\"UI_ACTION_REQUIRED\",\"source_action\":\"account_form.submit\"",
            "\"method\":\"GET\",\"path\":\"/catalog\",\"admission\":\"UI_ACTION_REQUIRED\",\"source_action\":\"account_form.submit\"",
        );
        assert!(matches!(
            GatewayConfig::from_json(duplicate.as_bytes()),
            Err(ConfigError::DuplicateRoute)
        ));
        let template = CONFIG.replace("/catalog", "/catalog/{id}");
        assert!(matches!(
            GatewayConfig::from_json(template.as_bytes()),
            Err(ConfigError::Invalid("operations.path"))
        ));
        let traversal = CONFIG.replace("target/xshield-audit-test", "../target/xshield-audit-test");
        assert!(matches!(
            GatewayConfig::from_json(traversal.as_bytes()),
            Err(ConfigError::Invalid("audit.directory"))
        ));
        let reserved = CONFIG.replace("/catalog", SENSOR_ASSET_PATH);
        assert!(matches!(
            GatewayConfig::from_json(reserved.as_bytes()),
            Err(ConfigError::Invalid("operations.path"))
        ));

        let invalid_heartbeat =
            CONFIG.replace("\"heartbeat_seconds\":15", "\"heartbeat_seconds\":4");
        assert!(matches!(
            GatewayConfig::from_json(invalid_heartbeat.as_bytes()),
            Err(ConfigError::Invalid("sensor.heartbeat_seconds"))
        ));
        let invalid_build = CONFIG.replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "not-a-build",
        );
        assert!(matches!(
            GatewayConfig::from_json(invalid_build.as_bytes()),
            Err(ConfigError::Provenance(_))
        ));
        let invalid_origin = CONFIG.replace("https://app.example", "http://app.example");
        assert!(matches!(
            GatewayConfig::from_json(invalid_origin.as_bytes()),
            Err(ConfigError::Invalid("sensor.origin"))
        ));
    }

    #[test]
    fn validates_identity_store_bounds() {
        let configured = CONFIG.to_owned();
        let config = GatewayConfig::from_json(configured.as_bytes()).unwrap();
        let identity = config.identity_store().unwrap();
        assert_eq!(identity.max_connections(), 4);
        assert_eq!(identity.acquire_timeout_ms(), 1000);
        assert_eq!(identity.anonymous_session_ttl_seconds(), 3_600);
        assert_eq!(identity.max_active_anonymous_sessions(), 100_000);
        assert_eq!(identity.anonymous_session_rate_window_seconds(), 60);
        assert_eq!(identity.max_anonymous_session_creations_per_source(), 10);
        assert_eq!(identity.max_anonymous_session_creations_per_site(), 1_000);

        let invalid = configured.replace("\"max_connections\":4", "\"max_connections\":0");
        assert!(matches!(
            GatewayConfig::from_json(invalid.as_bytes()),
            Err(ConfigError::Invalid("identity_store"))
        ));

        let invalid_ttl = configured.replace(
            "\"acquire_timeout_ms\":1000",
            "\"acquire_timeout_ms\":1000,\"anonymous_session_ttl_seconds\":86401",
        );
        assert!(matches!(
            GatewayConfig::from_json(invalid_ttl.as_bytes()),
            Err(ConfigError::Invalid("identity_store"))
        ));

        let invalid_capacity = configured.replace(
            "\"acquire_timeout_ms\":1000",
            "\"acquire_timeout_ms\":1000,\"max_active_anonymous_sessions\":1000001",
        );
        assert!(matches!(
            GatewayConfig::from_json(invalid_capacity.as_bytes()),
            Err(ConfigError::Invalid("identity_store"))
        ));

        let invalid_rate = configured.replace(
            "\"acquire_timeout_ms\":1000",
            "\"acquire_timeout_ms\":1000,\"max_anonymous_session_creations_per_source\":1001",
        );
        assert!(matches!(
            GatewayConfig::from_json(invalid_rate.as_bytes()),
            Err(ConfigError::Invalid("identity_store"))
        ));

        let missing = CONFIG.replace(
            "      \"identity_store\":{\"max_connections\":4,\"acquire_timeout_ms\":1000},\n",
            "",
        );
        assert!(matches!(
            GatewayConfig::from_json(missing.as_bytes()),
            Err(ConfigError::Invalid("identity_store"))
        ));

        let invalid_segment = CONFIG.replace(
            "\"segment_max_bytes\":262144",
            "\"segment_max_bytes\":2097152",
        );
        assert!(matches!(
            GatewayConfig::from_json(invalid_segment.as_bytes()),
            Err(ConfigError::Journal(
                xshield_audit::JournalError::InvalidLimits
            ))
        ));

        let invalid_reconcile = CONFIG.replace(
            "\"segment_max_bytes\":262144",
            "\"segment_max_bytes\":262144,\"reconcile_max_records\":0",
        );
        assert!(matches!(
            GatewayConfig::from_json(invalid_reconcile.as_bytes()),
            Err(ConfigError::Invalid("audit.reconcile_max_records"))
        ));
    }

    #[test]
    fn compiles_only_get_resource_query_adapters() {
        let resource = CONFIG
            .replace("\"method\":\"POST\",\"path\":\"/account\"", "\"method\":\"GET\",\"path\":\"/account\"")
            .replace(
                "\"resource_type\":null,\"view_profile\":null}\n      ]",
                "\"resource_type\":\"account\",\"view_profile\":\"summary\",\"resource_query_parameter\":\"account_id\"}\n      ]",
            );
        let config = GatewayConfig::from_json(resource.as_bytes()).unwrap();
        let operation = config.resource_operation("GET", "/account").unwrap();
        assert!(matches!(
            operation.location,
            ResourceLocation::Query(parameter) if parameter.as_str() == "account_id"
        ));

        let non_get = resource.replace(
            "\"method\":\"GET\",\"path\":\"/account\"",
            "\"method\":\"POST\",\"path\":\"/account\"",
        );
        assert!(matches!(
            GatewayConfig::from_json(non_get.as_bytes()),
            Err(ConfigError::Invalid("operation capability"))
        ));
    }

    #[test]
    fn compiles_one_final_path_resource_segment() {
        let resource = CONFIG
            .replace(
                "\"method\":\"POST\",\"path\":\"/account\"",
                "\"method\":\"GET\",\"path\":\"/account/{account_id}\"",
            )
            .replace(
                "\"resource_type\":null,\"view_profile\":null}\n      ]",
                "\"resource_type\":\"account\",\"view_profile\":\"summary\",\"resource_path_parameter\":\"account_id\"}\n      ]",
            );
        let config = GatewayConfig::from_json(resource.as_bytes()).unwrap();
        let operation = config
            .resource_operation("GET", "/account/account-123")
            .unwrap();
        assert!(matches!(
            operation.location,
            ResourceLocation::FinalPathSegment { prefix: "/account/", parameter }
                if parameter.as_str() == "account_id"
        ));
        assert_eq!(
            config
                .admit("GET", "/account/account-123", UnixSeconds::new(1))
                .reason_code,
            ReasonCode::UiActionNotAvailable
        );
        assert!(
            config
                .resource_operation("GET", "/account/nested/account-123")
                .is_none()
        );

        let ambiguous =
            resource.replace("\"path\":\"/catalog\"", "\"path\":\"/account/account-123\"");
        assert!(matches!(
            GatewayConfig::from_json(ambiguous.as_bytes()),
            Err(ConfigError::DuplicateRoute)
        ));
        let wrong_marker = resource.replace("{account_id}", "{other_id}");
        assert!(matches!(
            GatewayConfig::from_json(wrong_marker.as_bytes()),
            Err(ConfigError::Invalid("operations.path"))
        ));
        let two_locations = resource.replace(
            "\"resource_path_parameter\":\"account_id\"",
            "\"resource_query_parameter\":\"account_id\",\"resource_path_parameter\":\"account_id\"",
        );
        assert!(matches!(
            GatewayConfig::from_json(two_locations.as_bytes()),
            Err(ConfigError::Invalid("operation capability"))
        ));
    }

    #[test]
    fn validates_bounded_json_response_configuration() {
        let buffered = CONFIG.replace(
            "\"operation_id\":\"catalog.read\"",
            "\"operation_id\":\"catalog.read\",\"response\":{\"mode\":\"BUFFERED_JSON\",\"max_bytes\":4096}",
        );
        let config = GatewayConfig::from_json(buffered.as_bytes()).unwrap();
        assert_eq!(
            config.buffered_json_max_bytes("GET", "/catalog"),
            Some(4096)
        );
        assert_eq!(config.buffered_json_max_bytes("POST", "/account"), None);

        let encrypted = buffered.replace(
            "\"max_bytes\":4096",
            "\"max_bytes\":4096,\"crypto\":{\"mode\":\"DIRECT_ENCRYPT\",\"adapter_revision\":\"catalog-response-r1\",\"key_id\":\"response-key-r1\",\"key_not_before\":1,\"key_expires_at\":4102444800,\"message_ttl_seconds\":60,\"max_envelope_bytes\":9216}",
        );
        let encrypted = GatewayConfig::from_json(encrypted.as_bytes()).unwrap();
        let crypto = encrypted.response_crypto_rule("GET", "/catalog").unwrap();
        assert_eq!(crypto.key_id(), "response-key-r1");
        assert_eq!(crypto.max_in_flight_bytes(), 21_520);
        assert_eq!(encrypted.response_crypto_key_id(), Some("response-key-r1"));

        let oversized = buffered.replace("\"max_bytes\":4096", "\"max_bytes\":16777217");
        assert!(matches!(
            GatewayConfig::from_json(oversized.as_bytes()),
            Err(ConfigError::Invalid("operations.response.max_bytes"))
        ));
    }

    #[test]
    fn listener_port_stays_inside_the_internal_pool() {
        let mut config: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        config["listen"] = "127.0.0.1:6099".into();
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()),
            Err(ConfigError::Invalid("listen.port"))
        ));
    }

    #[test]
    fn capture_requires_bounded_json_and_a_catalog_store() {
        let mut json: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        json["operations"][0]["response"] = serde_json::json!({
            "mode":"BUFFERED_JSON", "max_bytes":4096,
            "evidence_capture":{"profile_revision":"capture-r1", "max_bytes":1024,
                "retention_seconds":3600, "secret_pointers":["/credential"]}
        });
        json["operations"].as_array_mut().unwrap().truncate(1);
        json.as_object_mut().unwrap().remove("sensor");
        let config = GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(config.requires_evidence_capture());
        assert!(config.evidence_capture_rule("GET", "/catalog").is_some());
        json["operations"][0]["response"]["evidence_capture"]["max_bytes"] = 4097.into();
        assert!(GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
        json["operations"][0]["response"]["evidence_capture"]["max_bytes"] = 1024.into();
        json.as_object_mut().unwrap().remove("identity_store");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&json).unwrap()),
            Err(ConfigError::Invalid("identity_store"))
        ));
    }

    #[test]
    fn compiles_response_resources_to_one_exact_target_operation() {
        let config = serde_json::json!({
            "listen": "127.0.0.1:6188",
            "origin": {
                "address": "127.0.0.1:8080",
                "server_name": "origin.example",
                "tls": false
            },
            "tenant_id": "tenant_demo",
            "site_id": "site_demo",
            "policy_revision": "policy-r1",
            "audit": {
                "directory": "target/xshield-response-grant-test",
                "key_id": "journal-key-r1",
                "producer_id": "edge-test",
                "max_bytes": 1_048_576,
                "high_watermark_bytes": 786_432,
                "segment_max_bytes": 262_144
            },
            "identity_store": {"max_connections": 4, "acquire_timeout_ms": 1_000},
            "operations": [
                {
                    "operation_id": "orders.list",
                    "method": "GET",
                    "path": "/orders",
                    "admission": "AUTHENTICATED_ROOT",
                    "source_action": null,
                    "resource_type": null,
                    "view_profile": null,
                    "response": {
                        "mode": "BUFFERED_JSON",
                        "max_bytes": 4_096,
                        "resource_grant": {
                            "success_status": 200,
                            "items_pointer": "/orders",
                            "resource_pointer": "/id",
                            "action_ref_field": "_xshield_action_ref",
                            "target_operation_id": "orders.read",
                            "target_mapping_revision": "mapping-r1",
                            "ttl_seconds": 900,
                            "max_items": 100,
                            "max_active_grants": 5_000
                        }
                    }
                },
                {
                    "operation_id": "orders.read",
                    "method": "GET",
                    "path": "/orders/{order_id}",
                    "admission": "UI_ACTION_REQUIRED",
                    "source_action": "orders.open",
                    "resource_type": "order",
                    "view_profile": "customer_detail",
                    "resource_path_parameter": "order_id"
                }
            ]
        });
        let bytes = serde_json::to_vec(&config).unwrap();
        let compiled = GatewayConfig::from_json(&bytes).unwrap();
        let operation = compiled.response_grant_operation("GET", "/orders").unwrap();
        assert_eq!(operation.target_action_id.as_str(), "orders.open");
        assert_eq!(operation.target_mapping_revision.as_str(), "mapping-r1");
        assert_eq!(operation.resource_type.as_str(), "order");
        assert_eq!(operation.view_profile.as_str(), "customer_detail");
        assert_eq!(operation.target_field.as_str(), "order_id");
        assert_eq!(operation.rule.ttl_seconds(), 900);
        assert_eq!(operation.rule.max_active_grants(), 5_000);

        let mut missing_target = config.clone();
        missing_target["operations"][0]["response"]["resource_grant"]["target_operation_id"] =
            serde_json::json!("orders.missing");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&missing_target).unwrap()),
            Err(ConfigError::Invalid(
                "operations.response.target_operation_id"
            ))
        ));

        let mut public_source = config.clone();
        public_source["operations"][0]["admission"] = serde_json::json!("PUBLIC");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&public_source).unwrap()),
            Err(ConfigError::Invalid("operations.response.resource_grant"))
        ));

        let mut duplicate_id = config;
        duplicate_id["operations"][1]["operation_id"] = serde_json::json!("orders.list");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&duplicate_id).unwrap()),
            Err(ConfigError::Invalid("operations.operation_id"))
        ));
    }

    fn share_response_config() -> serde_json::Value {
        let mut config: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        config["operations"] = serde_json::json!([
            {
                "operation_id": "records.share.issue", "method": "GET", "path": "/share-issue",
                "admission": "UI_ACTION_REQUIRED", "source_action": "records.share.open",
                "resource_type": "record", "view_profile": "share_controls",
                "resource_query_parameter": "record_id",
                "response": {
                    "mode": "BUFFERED_JSON", "max_bytes": 4096,
                    "share_issue": {
                        "success_status": 200, "token_field": "share_token",
                        "target_operation_id": "records.share.read",
                        "issuance_rule_id": "record-share-r1",
                        "ttl_seconds": 300, "max_active_shares": 100
                    }
                }
            },
            {
                "operation_id": "records.share.read", "method": "GET", "path": "/shared-record",
                "admission": "SHARE_ENTRY", "source_action": null,
                "resource_type": "record", "view_profile": "shared_summary",
                "resource_query_parameter": "record_id"
            }
        ]);
        config
    }

    #[test]
    fn compiles_fixed_share_scope_and_independent_issuance_rule() {
        let config = share_response_config();
        let compiled = GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).unwrap();
        let operation = compiled
            .response_share_operation("GET", "/share-issue")
            .unwrap();
        assert!(compiled.requires_share_issuance());
        assert_eq!(
            operation.source_operation_id.as_str(),
            "records.share.issue"
        );
        assert_eq!(operation.source_view_profile.as_str(), "share_controls");
        assert_eq!(operation.resource_type.as_str(), "record");
        assert_eq!(operation.view_profile.as_str(), "shared_summary");
        assert_eq!(
            operation.rule.target_operation_id().as_str(),
            "records.share.read"
        );
        assert_eq!(
            operation.rule.issuance_rule_id().as_str(),
            "record-share-r1"
        );
        assert_eq!(operation.rule.success_status(), 200);
        assert_eq!(operation.rule.ttl_seconds(), 300);
        assert_eq!(operation.rule.max_active_shares(), 100);
        assert!(
            compiled
                .response_share_operation("GET", "/shared-record")
                .is_none()
        );
        assert!(
            !GatewayConfig::from_json(CONFIG.as_bytes())
                .unwrap()
                .requires_share_issuance()
        );

        for (pointer, value) in [
            ("/operations/0/source_action", serde_json::Value::Null),
            (
                "/operations/0/admission",
                serde_json::json!("AUTHENTICATED_ROOT"),
            ),
            ("/operations/0/resource_type", serde_json::Value::Null),
            ("/operations/1/admission", serde_json::json!("PUBLIC")),
            ("/operations/1/resource_type", serde_json::json!("patient")),
            ("/operations/1/method", serde_json::json!("POST")),
            (
                "/operations/0/response/share_issue/target_operation_id",
                serde_json::json!("records.missing"),
            ),
            (
                "/operations/0/response/share_issue/target_operation_id",
                serde_json::json!("records.share.issue"),
            ),
            (
                "/operations/0/response/mode",
                serde_json::json!("SENSOR_HTML"),
            ),
        ] {
            let mut invalid = config.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(
                GatewayConfig::from_json(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "{pointer}"
            );
        }

        let mut path_target = config;
        path_target["operations"][1]["path"] = serde_json::json!("/shared-record/{record_id}");
        path_target["operations"][1]["resource_path_parameter"] = serde_json::json!("record_id");
        path_target["operations"][1]
            .as_object_mut()
            .unwrap()
            .remove("resource_query_parameter");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&path_target).unwrap()),
            Err(ConfigError::Invalid("operations.response.share_issue"))
        ));
    }

    #[test]
    fn rejects_invalid_share_response_rule_parameters() {
        for (field, value) in [
            ("issuance_rule_id", serde_json::json!("")),
            ("token_field", serde_json::json!("bad field")),
            ("success_status", serde_json::json!(204)),
            ("success_status", serde_json::json!(205)),
            ("success_status", serde_json::json!(206)),
            ("success_status", serde_json::json!(500)),
            ("ttl_seconds", serde_json::json!(0)),
            ("ttl_seconds", serde_json::json!(86401)),
            ("max_active_shares", serde_json::json!(0)),
            ("max_active_shares", serde_json::json!(5001)),
            ("client_target", serde_json::json!("records.read")),
        ] {
            let mut invalid = share_response_config();
            invalid["operations"][0]["response"]["share_issue"][field] = value;
            assert!(
                GatewayConfig::from_json(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn share_issuance_is_exclusive_with_identity_and_resource_issuance() {
        for (field, rule) in [
            (
                "resource_grant",
                serde_json::json!({
                    "success_status": 200, "items_pointer": "/items", "resource_pointer": "/id",
                    "action_ref_field": "action_ref", "target_operation_id": "records.share.issue",
                    "target_mapping_revision": "mapping-r1", "ttl_seconds": 300,
                    "max_items": 10, "max_active_grants": 100
                }),
            ),
            (
                "auth_binding",
                serde_json::json!({
                    "success_status": 200, "principal_pointer": "/principal",
                    "authorization_context_pointer": "/context", "bearer_pointer": "/bearer",
                    "credential_ttl_seconds": 300, "session_ttl_seconds": 300
                }),
            ),
            (
                "auth_refresh",
                serde_json::json!({
                    "success_status": 200, "principal_pointer": "/principal",
                    "authorization_context_pointer": "/context", "bearer_pointer": "/bearer",
                    "credential_ttl_seconds": 300
                }),
            ),
            (
                "auth_context_switch",
                serde_json::json!({
                    "success_status": 200, "principal_pointer": "/principal",
                    "authorization_context_pointer": "/context", "bearer_pointer": "/bearer",
                    "credential_ttl_seconds": 300
                }),
            ),
        ] {
            let mut invalid = share_response_config();
            invalid["operations"][0]["response"][field] = rule;
            assert!(
                matches!(
                    GatewayConfig::from_json(&serde_json::to_vec(&invalid).unwrap()),
                    Err(ConfigError::Invalid("operations.response"))
                ),
                "{field}"
            );
        }
    }

    #[test]
    fn share_response_rejects_json_reparsing_encryption() {
        let mut config = share_response_config();
        config["operations"][0]["response"]["crypto"] = serde_json::json!({
            "mode": "DIRECT_ENCRYPT", "adapter_revision": "share-response-r1",
            "key_id": "response-key-r1", "key_not_before": 1,
            "key_expires_at": 4_102_444_800_u64, "message_ttl_seconds": 60,
            "max_envelope_bytes": 9216
        });
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()),
            Err(ConfigError::Invalid("operations.response.share_issue"))
        ));
        config["operations"][0]["response"]
            .as_object_mut()
            .unwrap()
            .remove("share_issue");
        assert!(GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).is_ok());
    }

    #[test]
    fn opaque_request_compilation_rejects_share_issuance_side_effects() {
        for mode in ["OBSERVE", "COMPATIBILITY"] {
            let mut invalid = share_response_config();
            let operation = &mut invalid["operations"][0];
            operation["method"] = serde_json::json!("POST");
            for field in ["resource_type", "view_profile", "resource_query_parameter"] {
                operation.as_object_mut().unwrap().remove(field);
            }
            operation["request_crypto"] = if mode == "COMPATIBILITY" {
                serde_json::json!({
                    "mode": mode, "adapter_revision": "share-opaque-r1", "approval_ref": "approval-r1",
                    "expires_at": 4_102_444_800_u64, "build_fingerprints": ["a".repeat(64)]
                })
            } else {
                operation["admission"] = serde_json::json!("AUTHENTICATED_ROOT");
                operation["source_action"] = serde_json::Value::Null;
                serde_json::json!({"mode": mode, "adapter_revision": "share-opaque-r1"})
            };
            assert!(matches!(
                GatewayConfig::from_json(&serde_json::to_vec(&invalid).unwrap()),
                Err(ConfigError::Invalid("operations.request_crypto"))
            ));
            invalid["operations"][0]["response"]
                .as_object_mut()
                .unwrap()
                .remove("share_issue");
            assert!(GatewayConfig::from_json(&serde_json::to_vec(&invalid).unwrap()).is_ok());
        }
    }

    fn auth_response_config() -> serde_json::Value {
        serde_json::json!({
            "listen": "127.0.0.1:6188",
            "origin": {"address": "127.0.0.1:8080", "server_name": "origin.example", "tls": false},
            "tenant_id": "tenant_demo",
            "site_id": "site_demo",
            "policy_revision": "policy-r1",
            "audit": {
                "directory": "target/xshield-auth-binding-test",
                "key_id": "journal-key-r1",
                "producer_id": "edge-test",
                "max_bytes": 1_048_576,
                "high_watermark_bytes": 786_432,
                "segment_max_bytes": 262_144
            },
            "identity_store": {"max_connections": 4, "acquire_timeout_ms": 1_000},
            "operations": [{
                "operation_id": "auth.login",
                "method": "POST",
                "path": "/login",
                "admission": "AUTH_ENTRY",
                "source_action": null,
                "resource_type": null,
                "view_profile": null,
                "response": {
                    "mode": "BUFFERED_JSON",
                    "max_bytes": 4_096,
                    "auth_binding": {
                        "success_status": 200,
                        "principal_pointer": "/identity/id",
                        "authorization_context_pointer": "/identity/authorization_context",
                        "bearer_pointer": "/access_token",
                        "credential_ttl_seconds": 900,
                        "session_ttl_seconds": 3_600
                    }
                }
            }]
        })
    }

    #[test]
    fn compiles_authentication_response_only_for_auth_entry() {
        let config = auth_response_config();
        let compiled = GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).unwrap();
        let rule = compiled.auth_binding_rule("POST", "/login").unwrap();
        assert_eq!(rule.credential_ttl_seconds(), 900);
        assert_eq!(rule.session_ttl_seconds(), 3_600);

        let mut public = config.clone();
        public["operations"][0]["admission"] = serde_json::json!("PUBLIC");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&public).unwrap()),
            Err(ConfigError::Invalid("operations.response.auth_binding"))
        ));

        let mut aliased_context = config.clone();
        aliased_context["operations"][0]["response"]["auth_binding"]["authorization_context_pointer"] =
            serde_json::json!("/identity/id");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&aliased_context).unwrap()),
            Err(ConfigError::Invalid("operations.response.auth_binding"))
        ));

        let mut refresh = config.clone();
        refresh["operations"][0]["admission"] = serde_json::json!("AUTHENTICATED_ROOT");
        let response = refresh["operations"][0]["response"]
            .as_object_mut()
            .unwrap();
        response.remove("auth_binding");
        response.insert(
            "auth_refresh".to_owned(),
            serde_json::json!({
                "success_status": 200,
                "principal_pointer": "/identity/id",
                "authorization_context_pointer": "/identity/authorization_context",
                "bearer_pointer": "/access_token",
                "credential_ttl_seconds": 900
            }),
        );
        let compiled = GatewayConfig::from_json(&serde_json::to_vec(&refresh).unwrap()).unwrap();
        assert_eq!(
            compiled
                .auth_refresh_rule("POST", "/login")
                .unwrap()
                .credential_ttl_seconds(),
            900
        );
        refresh["operations"][0]["admission"] = serde_json::json!("AUTH_ENTRY");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&refresh).unwrap()),
            Err(ConfigError::Invalid("operations.response.auth_refresh"))
        ));

        let mut context_switch = config.clone();
        context_switch["operations"][0]["admission"] = serde_json::json!("AUTHENTICATED_ROOT");
        let response = context_switch["operations"][0]["response"]
            .as_object_mut()
            .unwrap();
        response.remove("auth_binding");
        response.insert(
            "auth_context_switch".to_owned(),
            serde_json::json!({
                "success_status": 200,
                "principal_pointer": "/identity/id",
                "authorization_context_pointer": "/identity/authorization_context",
                "bearer_pointer": "/access_token",
                "credential_ttl_seconds": 900
            }),
        );
        let compiled =
            GatewayConfig::from_json(&serde_json::to_vec(&context_switch).unwrap()).unwrap();
        assert!(
            compiled
                .auth_context_switch_rule("POST", "/login")
                .is_some()
        );
        context_switch["operations"][0]["admission"] = serde_json::json!("AUTH_ENTRY");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&context_switch).unwrap()),
            Err(ConfigError::Invalid(
                "operations.response.auth_context_switch"
            ))
        ));

        let mut incoherent = config;
        incoherent["operations"][0]["response"]["auth_binding"]["credential_ttl_seconds"] =
            serde_json::json!(7200);
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&incoherent).unwrap()),
            Err(ConfigError::Invalid("operations.response.auth_binding"))
        ));
    }

    #[test]
    fn compiles_binding_revocation_only_for_authenticated_root() {
        let mut config = auth_response_config();
        config["operations"][0]["operation_id"] = serde_json::json!("auth.logout");
        config["operations"][0]["path"] = serde_json::json!("/logout");
        config["operations"][0]["admission"] = serde_json::json!("AUTHENTICATED_ROOT");
        config["operations"][0]["response"]
            .as_object_mut()
            .unwrap()
            .remove("auth_binding");
        config["operations"][0]["response"]["auth_revoke"] =
            serde_json::json!({"success_status": 204});
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()),
            Err(ConfigError::Invalid("operations.response.auth_revoke"))
        ));
        config["operations"][0]["response"]["auth_revoke"] =
            serde_json::json!({"success_status": 200});
        let compiled = GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(compiled.auth_revoke_rule("POST", "/logout").is_some());
        assert!(compiled.requires_identity_runtime());

        for status in [199, 204, 205, 206, 300] {
            let mut invalid = config.clone();
            invalid["operations"][0]["response"]["auth_revoke"]["success_status"] =
                serde_json::json!(status);
            assert!(matches!(
                GatewayConfig::from_json(&serde_json::to_vec(&invalid).unwrap()),
                Err(ConfigError::Invalid("operations.response.auth_revoke"))
            ));
        }
        let mut public = config.clone();
        public["operations"][0]["admission"] = serde_json::json!("PUBLIC");
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&public).unwrap()),
            Err(ConfigError::Invalid("operations.response.auth_revoke"))
        ));
        let mut combined = config;
        combined["operations"][0]["response"]["auth_refresh"] = serde_json::json!({
            "success_status": 200,
            "principal_pointer": "/identity/id",
            "authorization_context_pointer": "/identity/authorization_context",
            "bearer_pointer": "/access_token",
            "credential_ttl_seconds": 900
        });
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&combined).unwrap()),
            Err(ConfigError::Invalid("operations.response"))
        ));
    }

    #[test]
    fn compiles_one_bounded_direct_decryption_adapter() {
        let mut config: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        config["operations"][1]["admission"] = serde_json::json!("AUTHENTICATED_ROOT");
        config["operations"][1]["source_action"] = serde_json::Value::Null;
        config["operations"][1]["request_crypto"] = serde_json::json!({
            "mode": "DIRECT_DECRYPT",
            "adapter_revision": "account-json-r1",
            "key_id": "request-key-r1",
            "key_not_before": 1,
            "key_expires_at": 4_102_444_800_u64,
            "max_envelope_bytes": 4096,
            "max_plaintext_bytes": 1024,
            "max_message_age_seconds": 60,
            "max_future_skew_seconds": 5,
            "max_active_messages": 1000
        });
        let compiled = GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).unwrap();
        let rule = compiled.request_crypto_rule("POST", "/account").unwrap();
        assert_eq!(rule.adapter_revision(), "account-json-r1");
        assert_eq!(rule.max_in_flight_bytes(), 16_384);
        assert_eq!(compiled.request_crypto_key_id(), Some("request-key-r1"));

        config["operations"][1]["admission"] = serde_json::json!("UI_ACTION_REQUIRED");
        assert!(GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).is_err());
        config["operations"][1]["admission"] = serde_json::json!("AUTHENTICATED_ROOT");

        config["operations"][1]["request_crypto"]["max_envelope_bytes"] =
            serde_json::json!(MAX_ENCRYPTED_REQUEST_ENVELOPE_BYTES + 1);
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()),
            Err(ConfigError::Invalid("operations.request_crypto"))
        ));
    }

    #[test]
    fn observe_forwards_only_without_response_qualification_side_effects() {
        let mut config: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        config["operations"][1]["admission"] = serde_json::json!("AUTHENTICATED_ROOT");
        config["operations"][1]["source_action"] = serde_json::Value::Null;
        config["operations"][1]["request_crypto"] = serde_json::json!({
            "mode": "OBSERVE",
            "adapter_revision": "account-candidate-r2"
        });
        let compiled = GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(matches!(
            compiled.request_crypto_policy("POST", "/account"),
            Some(RequestCryptoPolicy::Observe(rule))
                if rule.adapter_revision() == "account-candidate-r2"
        ));
        assert!(compiled.request_crypto_rule("POST", "/account").is_none());
        assert_eq!(compiled.request_crypto_key_id(), None);

        config["operations"][1]["admission"] = serde_json::json!("AUTH_ENTRY");
        config["operations"][1]["response"] = serde_json::json!({
            "mode": "BUFFERED_JSON",
            "max_bytes": 1024,
            "auth_binding": {
                "success_status": 200,
                "principal_pointer": "/identity/id",
                "authorization_context_pointer": "/identity/context",
                "bearer_pointer": "/access_token",
                "credential_ttl_seconds": 900,
                "session_ttl_seconds": 3600
            }
        });
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()),
            Err(ConfigError::Invalid("operations.request_crypto"))
        ));
    }

    #[test]
    fn compatibility_is_ui_build_approval_scoped() {
        let mut config: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        config["operations"][1]["request_crypto"] = serde_json::json!({
            "mode": "COMPATIBILITY",
            "adapter_revision": "account-legacy-r2",
            "approval_ref": "approval-42",
            "expires_at": 4_102_444_800_u64,
            "build_fingerprints": [
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ]
        });
        let compiled = GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(matches!(
            compiled.request_crypto_policy("POST", "/account"),
            Some(RequestCryptoPolicy::Compatibility(rule))
                if rule.approval_ref() == "approval-42"
        ));

        config["operations"][1]["response"] = serde_json::json!({
            "mode": "BUFFERED_JSON",
            "max_bytes": 1024,
            "crypto": {
                "mode": "DIRECT_ENCRYPT",
                "adapter_revision": "account-response-r1",
                "key_id": "response-key-r1",
                "key_not_before": 1,
                "key_expires_at": 4_102_444_800_u64,
                "message_ttl_seconds": 60,
                "max_envelope_bytes": 3072
            }
        });
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()),
            Err(ConfigError::Invalid("operations.request_crypto"))
        ));
        config["operations"][1]
            .as_object_mut()
            .unwrap()
            .remove("response");
        config["operations"][1]["admission"] = serde_json::json!("AUTHENTICATED_ROOT");
        config["operations"][1]["source_action"] = serde_json::Value::Null;
        assert!(matches!(
            GatewayConfig::from_json(&serde_json::to_vec(&config).unwrap()),
            Err(ConfigError::Invalid("operations.request_crypto"))
        ));
    }
}
