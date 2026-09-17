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
    },
    audit::ReasonCode,
    domain::{ActionId, OperationId, ResourceType, SiteId, TenantId, ViewProfile},
    identity::UnixSeconds,
    provenance::{ActionTarget, HttpMethod, RouteTemplate},
};

/// Maximum accepted gateway configuration size.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

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
    policy: OperationPolicy,
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
    /// network values, non-exact paths, incoherent policies, or duplicate routes.
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
        let audit_limits = JournalLimits::new(dto.audit.max_bytes, dto.audit.high_watermark_bytes)
            .map_err(ConfigError::Journal)?;
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
        if dto.operations.is_empty() {
            return Err(ConfigError::Invalid("operations"));
        }

        let mut operations = BTreeMap::new();
        for operation in dto.operations {
            let (key, compiled) = compile_operation(operation)?;
            if operations.insert(key, compiled).is_some() {
                return Err(ConfigError::DuplicateRoute);
            }
        }
        if identity_store.is_none()
            && operations.values().any(|operation| {
                matches!(
                    operation.policy.admission_class(),
                    AdmissionClass::AuthenticatedRoot | AdmissionClass::UiActionRequired
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
            },
            identity_store,
            operations,
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

    /// Returns bounded identity-store settings when protected roots are enabled.
    #[must_use]
    pub const fn identity_store(&self) -> Option<IdentityStoreConfig> {
        self.identity_store
    }

    /// Applies the compiled exact-operation policy with no client-created proof.
    ///
    /// This MVP adapter can admit only public and authentication-entry routes.
    /// All identity, UI, share, and service entries fail closed until their
    /// authoritative proof loaders are connected.
    #[must_use]
    pub fn admit(&self, method: &str, path: &str, now: UnixSeconds) -> GatewayDecision {
        self.admit_with_proof(method, path, now, AdmissionProof::None)
    }

    /// Returns the proof class for an exact configured operation.
    #[must_use]
    pub fn admission_class(&self, method: &str, path: &str) -> Option<AdmissionClass> {
        self.operations
            .get(&(method.to_owned(), path.to_owned()))
            .map(|operation| operation.policy.admission_class())
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
        let Some(operation) = self.operations.get(&(method.to_owned(), path.to_owned())) else {
            return GatewayDecision {
                outcome: GatewayOutcome::Denied,
                operation_id: None,
                reason_code: ReasonCode::OperationNotMatched,
            };
        };
        let target = ActionTarget::None;
        let fields = BTreeSet::new();
        let request = AdmissionRequest {
            tenant_id: &self.tenant_id,
            site_id: &self.site_id,
            method: operation.method,
            route: &operation.route,
            target: &target,
            fields: &fields,
            resource: None,
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

fn compile_operation(
    dto: OperationDto,
) -> Result<((String, String), CompiledOperation), ConfigError> {
    let method = parse_method(&dto.method).ok_or(ConfigError::Invalid("operations.method"))?;
    if dto.path.contains(['{', '}']) {
        return Err(ConfigError::Invalid("operations.path"));
    }
    let route = RouteTemplate::parse(dto.path.clone()).map_err(ConfigError::Provenance)?;
    let source_action = dto
        .source_action
        .map(ActionId::parse)
        .transpose()
        .map_err(ConfigError::Domain)?;
    let capability = match (dto.resource_type, dto.view_profile) {
        (None, None) => CapabilityPolicy::None,
        (Some(resource_type), Some(view_profile)) => CapabilityPolicy::ExactResource {
            resource_type: ResourceType::parse(resource_type).map_err(ConfigError::Domain)?,
            view_profile: ViewProfile::parse(view_profile).map_err(ConfigError::Domain)?,
        },
        _ => return Err(ConfigError::Invalid("operation capability")),
    };
    let policy = OperationPolicy::new(
        OperationId::parse(dto.operation_id).map_err(ConfigError::Domain)?,
        method,
        route.clone(),
        dto.admission.into(),
        source_action,
        capability,
    )
    .map_err(ConfigError::Policy)?;
    Ok((
        (method.as_str().to_owned(), dto.path),
        CompiledOperation {
            method,
            route,
            policy,
        },
    ))
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
      "audit":{"directory":"target/xshield-audit-test","key_id":"journal-key-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432},
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
    }
}
