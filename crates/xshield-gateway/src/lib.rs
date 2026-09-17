//! Validated runtime configuration and deterministic admission for the Pingora edge.

#![warn(missing_docs)]

use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};
use xshield_audit::JournalLimits;
use xshield_core::{
    admission::{
        AdmissionClass, AdmissionProof, AdmissionRequest, CapabilityPolicy, OperationPolicy,
        ResourceAccess,
    },
    audit::ReasonCode,
    domain::{
        ActionId, FieldName, MappingRevision, OperationId, ResourceType, SiteId, TenantId,
        ViewProfile,
    },
    grant::ResourceKeyHmac,
    identity::UnixSeconds,
    provenance::{ActionTarget, HttpMethod, RouteTemplate},
};

pub mod response_grant;
pub mod share_issue;
pub mod share_token;

use response_grant::ResponseGrantRule;

/// Maximum accepted gateway configuration size.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// Maximum complete private JSON response accepted by the MVP adapter.
pub const MAX_BUFFERED_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATH_RESOURCE_OPERATIONS: usize = 64;

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
    operations: BTreeMap<(String, String), CompiledOperation>,
    path_resource_operations: Vec<CompiledOperation>,
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
    reconcile_max_records: u64,
}

/// Bounded `PostgreSQL` identity lookup settings for protected roots.
#[derive(Clone, Copy, Debug)]
pub struct IdentityStoreConfig {
    max_connections: u32,
    acquire_timeout_ms: u64,
}

#[derive(Debug)]
struct CompiledOperation {
    method: HttpMethod,
    route: RouteTemplate,
    route_match: CompiledRouteMatch,
    policy: OperationPolicy,
    source_action: Option<ActionId>,
    resource: Option<CompiledResource>,
    response: Option<CompiledResponse>,
}

#[derive(Debug)]
struct CompiledResponse {
    max_bytes: usize,
    grant: Option<ResponseGrantRule>,
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
    operations: Vec<OperationDto>,
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
    response: Option<ResponseDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseDto {
    mode: ResponseModeDto,
    max_bytes: usize,
    #[serde(default)]
    resource_grant: Option<ResponseGrantDto>,
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

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ResponseModeDto {
    BufferedJson,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AdmissionDto {
    Public,
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
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid("configuration size"));
        }
        let dto: ConfigDto = serde_json::from_slice(bytes).map_err(ConfigError::Json)?;
        let listen = dto
            .listen
            .parse()
            .map_err(|_| ConfigError::Invalid("listen"))?;
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
            .map(|identity| {
                if identity.max_connections == 0
                    || identity.max_connections > 64
                    || identity.acquire_timeout_ms == 0
                    || identity.acquire_timeout_ms > 30_000
                {
                    return Err(ConfigError::Invalid("identity_store"));
                }
                Ok(IdentityStoreConfig {
                    max_connections: identity.max_connections,
                    acquire_timeout_ms: identity.acquire_timeout_ms,
                })
            })
            .transpose()?;
        let compiled_operations = compile_operations(dto.operations)?;
        if identity_store.is_none()
            && compiled_operations
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
                    )
                })
        {
            return Err(ConfigError::Invalid("identity_store"));
        }
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
                reconcile_max_records: dto.audit.reconcile_max_records,
            },
            identity_store,
            operations: compiled_operations.exact,
            path_resource_operations: compiled_operations.path_resources,
        })
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
        self.operation(method, path)
            .map(|operation| operation.policy.admission_class())
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
        Some(self.operation(method, path)?.response.as_ref()?.max_bytes)
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
        let Some(operation) = self.operation(method, path) else {
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
    validate_response_grants(&exact, &path_resources)?;
    Ok(CompiledOperations {
        exact,
        path_resources,
    })
}

fn validate_response_grants(
    exact: &BTreeMap<(String, String), CompiledOperation>,
    path_resources: &[CompiledOperation],
) -> Result<(), ConfigError> {
    let operations = exact.values().chain(path_resources);
    for source in operations.clone() {
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
}

fn compile_operation(dto: OperationDto) -> Result<CompiledOperation, ConfigError> {
    let method = parse_method(&dto.method).ok_or(ConfigError::Invalid("operations.method"))?;
    if dto.path.contains(['{', '}']) && dto.resource_path_parameter.is_none() {
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
    let response = dto.response.map(compile_response).transpose()?;
    Ok(CompiledOperation {
        method,
        route,
        route_match,
        policy,
        source_action,
        resource,
        response,
    })
}

fn compile_response(dto: ResponseDto) -> Result<CompiledResponse, ConfigError> {
    if !matches!(dto.mode, ResponseModeDto::BufferedJson)
        || !(1..=MAX_BUFFERED_JSON_BYTES).contains(&dto.max_bytes)
    {
        return Err(ConfigError::Invalid("operations.response.max_bytes"));
    }
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
    Ok(CompiledResponse {
        max_bytes: dto.max_bytes,
        grant,
    })
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
    }

    #[test]
    fn validates_identity_store_bounds() {
        let configured = CONFIG.to_owned();
        let config = GatewayConfig::from_json(configured.as_bytes()).unwrap();
        let identity = config.identity_store().unwrap();
        assert_eq!(identity.max_connections(), 4);
        assert_eq!(identity.acquire_timeout_ms(), 1000);

        let invalid = configured.replace("\"max_connections\":4", "\"max_connections\":0");
        assert!(matches!(
            GatewayConfig::from_json(invalid.as_bytes()),
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

        let oversized = buffered.replace("\"max_bytes\":4096", "\"max_bytes\":16777217");
        assert!(matches!(
            GatewayConfig::from_json(oversized.as_bytes()),
            Err(ConfigError::Invalid("operations.response.max_bytes"))
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
}
