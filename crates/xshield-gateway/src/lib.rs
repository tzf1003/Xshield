//! Validated runtime configuration and deterministic admission for the Pingora edge.

#![warn(missing_docs)]

use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
};
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
    operations: BTreeMap<(String, String), CompiledOperation>,
}

#[derive(Debug)]
struct Origin {
    address: SocketAddr,
    server_name: String,
    tls: bool,
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
    operations: Vec<OperationDto>,
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
        Ok(Self {
            listen,
            origin: Origin {
                address: origin_address,
                server_name: dto.origin.server_name,
                tls: dto.origin.tls,
            },
            tenant_id,
            site_id,
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

    /// Applies the compiled exact-operation policy with no client-created proof.
    ///
    /// This MVP adapter can admit only public and authentication-entry routes.
    /// All identity, UI, share, and service entries fail closed until their
    /// authoritative proof loaders are connected.
    #[must_use]
    pub fn admit(&self, method: &str, path: &str, now: UnixSeconds) -> GatewayDecision {
        let Some(operation) = self.operations.get(&(method.to_owned(), path.to_owned())) else {
            return GatewayDecision::Denied(ReasonCode::OperationNotMatched);
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
        match operation.policy.admit(request, AdmissionProof::None) {
            Ok(decision) => GatewayDecision::Allowed(decision.reason_code),
            Err(error) => GatewayDecision::Denied(error.reason_code()),
        }
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

/// Terminal admission result exposed to the network adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayDecision {
    /// The exact route can be forwarded.
    Allowed(ReasonCode),
    /// The request must terminate before origin dispatch.
    Denied(ReasonCode),
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
      "operations":[
        {"operation_id":"catalog.read","method":"GET","path":"/catalog","admission":"PUBLIC","source_action":null,"resource_type":null,"view_profile":null},
        {"operation_id":"account.update","method":"POST","path":"/account","admission":"UI_ACTION_REQUIRED","source_action":"account_form.submit","resource_type":null,"view_profile":null}
      ]
    }"#;

    #[test]
    fn admits_only_exact_unprotected_routes() {
        let config = GatewayConfig::from_json(CONFIG.as_bytes()).unwrap();
        assert_eq!(
            config.admit("GET", "/catalog", UnixSeconds::new(1)),
            GatewayDecision::Allowed(ReasonCode::PublicEntryAllowed)
        );
        assert_eq!(
            config.admit("POST", "/account", UnixSeconds::new(1)),
            GatewayDecision::Denied(ReasonCode::UiActionNotAvailable)
        );
        assert_eq!(
            config.admit("GET", "/catalog/1", UnixSeconds::new(1)),
            GatewayDecision::Denied(ReasonCode::OperationNotMatched)
        );
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
    }
}
