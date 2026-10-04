#![allow(clippy::map_unwrap_or)]

use super::{AccessAction, ControlPlane, audit_unavailable, internal_error, single_header};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use openidconnect::{
    AccessTokenHash, AuthenticationContextClass, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use openssl::{memcmp, rand::rand_bytes, sha::sha256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;
use xshield_core::{
    admin::{ManagementPrincipal, ManagementRole},
    domain::{SiteId, TenantId},
};

pub(super) const LOGIN_PATH: &str = "/control/v1/auth/oidc/start";
pub(super) const CALLBACK_PATH: &str = "/control/v1/auth/oidc/callback";
pub(super) const SESSION_PATH: &str = "/control/v1/session";
pub(super) const LOGOUT_PATH: &str = "/control/v1/session/logout";
pub(super) const REAUTH_START_PATH: &str = "/control/v1/auth/oidc/reauth/start";
pub(super) const API_KEY_HEADER: &str = "x-xshield-api-key";
const AGENT_RUN_HEADER: &str = "x-xshield-agent-run-id";
const SESSION_COOKIE: &str = "__Host-xshield-session";
const STATE_COOKIE: &str = "__Host-xshield-oidc-state";
const CSRF_HEADER: &str = "x-xshield-csrf";
const STATE_BYTES_MAX: usize = 128;
const CALLBACK_QUERY_BYTES_MAX: usize = 8_192;
const BROWSER_SESSION_LIFETIME_SECONDS: u64 = 8 * 60 * 60;
const STEP_UP_AUTH_TIME_MAX_AGE_SECONDS: u64 = 60;

pub(super) const LOGIN_ACCESS: AccessAction = AccessAction {
    event_type: "console.auth.login",
    method: "GET",
    path: LOGIN_PATH,
    role: ManagementRole::Observer,
};
pub(super) const CALLBACK_ACCESS: AccessAction = AccessAction {
    event_type: "console.auth.callback",
    method: "GET",
    path: CALLBACK_PATH,
    role: ManagementRole::Observer,
};
pub(super) const SESSION_READ_ACCESS: AccessAction = AccessAction {
    event_type: "console.auth.session.read",
    method: "GET",
    path: SESSION_PATH,
    role: ManagementRole::Observer,
};
pub(super) const SESSION_LOGOUT_ACCESS: AccessAction = AccessAction {
    event_type: "console.auth.session.logout",
    method: "POST",
    path: LOGOUT_PATH,
    role: ManagementRole::Observer,
};
pub(super) const REAUTH_START_ACCESS: AccessAction = AccessAction {
    event_type: "console.auth.reauth.start",
    method: "POST",
    path: REAUTH_START_PATH,
    role: ManagementRole::SensitiveEvidenceReader,
};
const REAUTH_CALLBACK_ACCESS: AccessAction = AccessAction {
    event_type: "console.auth.reauth.callback",
    method: "GET",
    path: CALLBACK_PATH,
    role: ManagementRole::SensitiveEvidenceReader,
};
pub(super) const API_KEY_ACCESS: AccessAction = AccessAction {
    event_type: "console.agent_api_key.use",
    method: "*",
    path: "/control/v1/*",
    role: ManagementRole::Observer,
};

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// OIDC provider client and deployment-owned identity allowlist.
pub struct OidcProvider {
    client: OidcClient,
    http: reqwest::Client,
    issuer: String,
    console_origin: String,
    required_acr: AuthenticationContextClass,
    subject_roles: BTreeMap<String, std::collections::BTreeSet<ManagementRole>>,
}

impl OidcProvider {
    /// Discovers one OIDC issuer and validates the fixed human-console origin.
    ///
    /// Redirects are disabled for provider traffic. `IdP` identity claims do not
    /// supply roles; each exact subject must exist in `subject_roles`.
    ///
    /// # Errors
    /// Returns a safe configuration/discovery error for invalid URLs, an
    /// untrusted MFA ACR value, an empty role mapping, or unavailable metadata.
    pub async fn discover(
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        console_origin: &str,
        required_acr: &str,
        subject_roles: BTreeMap<String, std::collections::BTreeSet<ManagementRole>>,
    ) -> Result<Self, IdentityConfigError> {
        let issuer_url = secure_url(issuer, false)?;
        let allow_loopback_endpoints = is_loopback_host(&issuer_url);
        let origin_url = secure_url(console_origin, true)?;
        if origin_url.path() != "/"
            || origin_url.query().is_some()
            || origin_url.fragment().is_some()
            || !origin_url.username().is_empty()
            || origin_url.password().is_some()
            || origin_url.origin().ascii_serialization() != console_origin
            || client_id.is_empty()
            || client_id.len() > 512
            || client_id.chars().any(char::is_control)
            || client_secret.is_empty()
            || required_acr.is_empty()
            || required_acr.trim() != required_acr
            || required_acr.len() > 256
            || required_acr.chars().any(char::is_control)
            || subject_roles.is_empty()
            || subject_roles.iter().any(|(subject, roles)| {
                subject.is_empty()
                    || subject.len() > 256
                    || subject.trim() != subject
                    || subject.chars().any(char::is_control)
                    || roles.is_empty()
            })
        {
            return Err(IdentityConfigError::Invalid);
        }
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| IdentityConfigError::Unavailable)?;
        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string()).map_err(|_| IdentityConfigError::Invalid)?,
            &http,
        )
        .await
        .map_err(|_| IdentityConfigError::Unavailable)?;
        if provider_metadata.issuer().as_str() != issuer
            || !endpoint_is_secure(
                provider_metadata.authorization_endpoint().as_str(),
                allow_loopback_endpoints,
            )
            || !provider_metadata.token_endpoint().is_some_and(|endpoint| {
                endpoint_is_secure(endpoint.as_str(), allow_loopback_endpoints)
            })
            || !endpoint_is_secure(
                provider_metadata.jwks_uri().as_str(),
                allow_loopback_endpoints,
            )
        {
            return Err(IdentityConfigError::Invalid);
        }
        let callback = format!("{console_origin}{CALLBACK_PATH}");
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(client_id.to_owned()),
            Some(ClientSecret::new(client_secret.to_owned())),
        )
        .set_redirect_uri(RedirectUrl::new(callback).map_err(|_| IdentityConfigError::Invalid)?);
        Ok(Self {
            client,
            http,
            issuer: issuer.to_owned(),
            console_origin: console_origin.to_owned(),
            required_acr: AuthenticationContextClass::new(required_acr.to_owned()),
            subject_roles,
        })
    }
}

/// Safe startup failure for control-plane OIDC configuration.
#[derive(Debug)]
pub enum IdentityConfigError {
    /// A configured identity value violates its strict boundary.
    Invalid,
    /// OIDC discovery or its bounded HTTP client is unavailable.
    Unavailable,
}

impl std::fmt::Display for IdentityConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => formatter.write_str("invalid OIDC configuration"),
            Self::Unavailable => formatter.write_str("OIDC provider unavailable"),
        }
    }
}

impl std::error::Error for IdentityConfigError {}

fn secure_url(value: &str, origin_only: bool) -> Result<Url, IdentityConfigError> {
    let url = Url::parse(value).map_err(|_| IdentityConfigError::Invalid)?;
    if !(url.scheme() == "https" || is_loopback_http(&url))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || origin_only && url.query().is_some()
    {
        return Err(IdentityConfigError::Invalid);
    }
    Ok(url)
}

fn is_loopback_http(url: &Url) -> bool {
    url.scheme() == "http" && is_loopback_host(url)
}

fn is_loopback_host(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1"))
}

fn endpoint_is_secure(value: &str, allow_loopback: bool) -> bool {
    secure_url(value, false).is_ok_and(|url| {
        if is_loopback_host(&url) {
            allow_loopback
        } else {
            url.scheme() == "https"
        }
    })
}

/// Request-local result of authenticating a machine bearer or browser cookie.
#[derive(Clone, Default)]
pub(super) struct AuthContext {
    pub(super) principal: Option<ManagementPrincipal>,
    pub(super) csrf_token: Option<String>,
    pub(super) session_digest: Option<[u8; 32]>,
    pub(super) step_up_valid: bool,
    pub(super) session_expires_at: Option<DateTime<Utc>>,
    pub(super) idle_expires_at: Option<DateTime<Utc>>,
    pub(super) last_reauthenticated_at: Option<DateTime<Utc>>,
    pub(super) direct_apply: bool,
    assertion: Option<BrowserRequestAssertion>,
    state: AuthState,
}

impl AuthContext {
    fn is_browser(&self) -> bool {
        matches!(self.state, AuthState::Browser { .. })
    }

    fn is_unavailable(&self) -> bool {
        matches!(self.state, AuthState::Unavailable)
    }

    fn csrf_valid(&self) -> bool {
        matches!(self.state, AuthState::Browser { csrf_valid: true })
    }

    pub(crate) const fn step_up_valid(&self) -> bool {
        self.step_up_valid
    }

    pub(crate) const fn is_browser_session(&self) -> bool {
        matches!(self.state, AuthState::Browser { .. })
    }
}

#[derive(Clone, Copy, Default)]
enum AuthState {
    #[default]
    Anonymous,
    Machine,
    Browser {
        csrf_valid: bool,
    },
    Unavailable,
    AmbiguousCredentials,
}

// The flags are independent fields of the signed assertion's wire format;
// folding them into an enum would change the authenticated representation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserRequestAssertion {
    version: u8,
    subject: String,
    tenant_id: String,
    site_id: String,
    #[serde(default)]
    tenant_scope: bool,
    #[serde(default)]
    machine: bool,
    #[serde(default)]
    direct_apply: bool,
    #[serde(default)]
    scopes: Vec<(String, String)>,
    roles: Vec<String>,
    csrf_valid: bool,
    expires_at: u64,
}

pub(super) struct VerifiedRequestIdentity {
    pub(super) principal: ManagementPrincipal,
    pub(super) browser: bool,
    pub(super) csrf_valid: bool,
    pub(super) direct_apply: bool,
}

const ASSERTION_PREFIX: &str = "Xshield-Session ";
const ASSERTION_DOMAIN: &[u8] = b"xshield-control-browser-request-v1";

pub(super) fn verify_request_assertion(
    token: &str,
    key: &[u8; 32],
) -> Option<VerifiedRequestIdentity> {
    let encoded = token.strip_prefix(ASSERTION_PREFIX)?;
    let (payload_hex, signature_hex) = encoded.split_once('.')?;
    if payload_hex.is_empty() || payload_hex.len() > 8_192 || signature_hex.len() != 64 {
        return None;
    }
    let payload = decode_hex(payload_hex)?;
    let signature = decode_hex(signature_hex)?;
    if signature.len() != 32 {
        return None;
    }
    let expected = super::component_signature(key, &[ASSERTION_DOMAIN, &payload]).ok()?;
    if !memcmp::eq(&expected, &signature) {
        return None;
    }
    let assertion: BrowserRequestAssertion = serde_json::from_slice(&payload).ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if assertion.version != 1
        || assertion.expires_at <= now
        || assertion.expires_at > now.saturating_add(60)
        || assertion.roles.is_empty()
        || assertion.roles.len() > 10
    {
        return None;
    }
    let machine = assertion.machine;
    let tenant_id = TenantId::parse(assertion.tenant_id).ok()?;
    let site_id = SiteId::parse(assertion.site_id).ok()?;
    let mut roles = std::collections::BTreeSet::new();
    for role in assertion.roles {
        if !roles.insert(parse_role(&role)?) {
            return None;
        }
    }
    let mut exact_scopes = vec![(tenant_id.clone(), site_id.clone())];
    for (tenant, site) in assertion.scopes {
        let pair = (TenantId::parse(tenant).ok()?, SiteId::parse(site).ok()?);
        if !exact_scopes.contains(&pair) {
            exact_scopes.push(pair);
        }
    }
    let principal = if assertion.tenant_scope {
        let mut principal =
            ManagementPrincipal::new_tenant_scoped(assertion.subject, roles, [tenant_id.clone()])
                .ok()?;
        for (tenant, site) in exact_scopes {
            principal = principal.with_exact_site_scope(tenant, site);
        }
        principal
    } else {
        ManagementPrincipal::new(assertion.subject, roles, exact_scopes).ok()?
    };
    Some(VerifiedRequestIdentity {
        principal,
        browser: !machine,
        csrf_valid: assertion.csrf_valid,
        direct_apply: assertion.direct_apply,
    })
}

fn sign_request_assertion(assertion: &BrowserRequestAssertion, key: &[u8; 32]) -> Option<String> {
    let payload = serde_json::to_vec(assertion).ok()?;
    let signature = super::component_signature(key, &[ASSERTION_DOMAIN, &payload]).ok()?;
    Some(format!(
        "{ASSERTION_PREFIX}{}.{}",
        lower_hex(&payload),
        lower_hex(&signature),
    ))
}

fn role_name(role: ManagementRole) -> &'static str {
    match role {
        ManagementRole::Observer => "observer",
        ManagementRole::Investigator => "investigator",
        ManagementRole::SensitiveEvidenceReader => "sensitive_evidence_reader",
        ManagementRole::SensitiveEvidenceApprover => "sensitive_evidence_approver",
        ManagementRole::PolicyAuthor => "policy_author",
        ManagementRole::PolicyApprover => "policy_approver",
        ManagementRole::ReleaseOperator => "release_operator",
        ManagementRole::AuditAdministrator => "audit_administrator",
        ManagementRole::KeyAdministrator => "key_administrator",
        ManagementRole::SystemAdmin => "system_admin",
    }
}

fn parse_role(value: &str) -> Option<ManagementRole> {
    Some(match value {
        "observer" => ManagementRole::Observer,
        "investigator" => ManagementRole::Investigator,
        "sensitive_evidence_reader" => ManagementRole::SensitiveEvidenceReader,
        "sensitive_evidence_approver" => ManagementRole::SensitiveEvidenceApprover,
        "policy_author" => ManagementRole::PolicyAuthor,
        "policy_approver" => ManagementRole::PolicyApprover,
        "release_operator" => ManagementRole::ReleaseOperator,
        "audit_administrator" => ManagementRole::AuditAdministrator,
        "key_administrator" => ManagementRole::KeyAdministrator,
        "system_admin" => ManagementRole::SystemAdmin,
        _ => return None,
    })
}

pub(super) async fn auth_middleware(
    State(control): State<std::sync::Arc<ControlPlane>>,
    mut request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let is_auth_endpoint = matches!(
        request.uri().path(),
        LOGIN_PATH | CALLBACK_PATH | SESSION_PATH | LOGOUT_PATH | REAUTH_START_PATH
    );
    let ambiguous = (cookie_name_present(request.headers(), SESSION_COOKIE)
        && request.headers().contains_key(header::AUTHORIZATION))
        || (request.headers().contains_key(API_KEY_HEADER)
            && (cookie_name_present(request.headers(), SESSION_COOKIE)
                || request.headers().contains_key(header::AUTHORIZATION)));
    let mut context = if ambiguous {
        AuthContext {
            state: AuthState::AmbiguousCredentials,
            ..AuthContext::default()
        }
    } else {
        resolve_auth(
            &control,
            request.method(),
            request.uri().path(),
            request.headers(),
        )
        .await
    };
    #[cfg(test)]
    {
        context.step_up_valid |= control.test_step_up_valid;
    }
    // Normalize malformed or ambiguous Authorization before downstream
    // handlers inspect the request, so a rejected value cannot be
    // reinterpreted as a valid first value.
    if request.headers().contains_key(header::AUTHORIZATION)
        && single_header(request.headers(), header::AUTHORIZATION.as_str()).is_none()
    {
        request.headers_mut().remove(header::AUTHORIZATION);
    }
    if request.headers().contains_key(API_KEY_HEADER)
        && single_header(request.headers(), API_KEY_HEADER).is_none()
    {
        request.headers_mut().remove(API_KEY_HEADER);
    }
    if matches!(context.state, AuthState::AmbiguousCredentials) {
        request.headers_mut().remove(header::AUTHORIZATION);
    }
    if let Some(assertion) = context.assertion.as_ref() {
        let signed = control
            .auth_context_key
            .as_deref()
            .and_then(|key| sign_request_assertion(assertion, key));
        if let Some(value) = signed.and_then(|value| HeaderValue::from_str(&value).ok()) {
            request.headers_mut().insert(header::AUTHORIZATION, value);
        } else {
            request.headers_mut().remove(header::AUTHORIZATION);
            context.principal = None;
            context.state = AuthState::Unavailable;
        }
    }
    request.extensions_mut().insert(context);
    let mut response = next.run(request).await;
    if is_auth_endpoint {
        no_store(&mut response);
    }
    response
}

async fn resolve_auth(
    control: &ControlPlane,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> AuthContext {
    if matches!(path, LOGIN_PATH | CALLBACK_PATH) {
        return AuthContext::default();
    }
    let authorization = single_header(headers, header::AUTHORIZATION.as_str());
    let api_key = single_header(headers, API_KEY_HEADER);
    let cookie = cookie_value(headers, SESSION_COOKIE);
    if api_key.is_some() {
        let agent_run = single_header(headers, AGENT_RUN_HEADER);
        if agent_run
            .as_deref()
            .is_none_or(|value| value.is_empty() || value.len() > 128)
        {
            return AuthContext::default();
        }
        return resolve_api_key(control, api_key.unwrap_or_default()).await;
    }
    if authorization.is_some() && cookie.is_some() {
        return AuthContext {
            state: AuthState::AmbiguousCredentials,
            ..AuthContext::default()
        };
    }
    if let Some(value) = authorization {
        return resolve_machine_auth(control, &value);
    }
    let Some(cookie) = cookie else {
        return AuthContext::default();
    };
    resolve_browser_auth(control, method, headers, &cookie).await
}

async fn resolve_api_key(control: &ControlPlane, value: String) -> AuthContext {
    let request_id = request_id();
    let Ok(identity) = control
        .authenticate_api_key(&value, &request_id, API_KEY_ACCESS)
        .await
    else {
        return AuthContext::default();
    };
    let Some(now) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
    else {
        return AuthContext {
            state: AuthState::Unavailable,
            ..AuthContext::default()
        };
    };
    let roles = identity
        .principal
        .roles()
        .iter()
        .copied()
        .map(role_name)
        .map(str::to_owned)
        .collect();
    let (tenant_id, site_id) = identity
        .principal
        .first_exact_site_scope()
        .map(|(tenant, site)| (tenant.as_str().to_owned(), site.as_str().to_owned()))
        .unwrap_or_else(|| {
            (
                control.config.tenant_id.as_str().to_owned(),
                control.config.site_id.as_str().to_owned(),
            )
        });
    let scopes = identity
        .principal
        .exact_site_scopes()
        .map(|(tenant, site)| (tenant.as_str().to_owned(), site.as_str().to_owned()))
        .collect();
    let assertion = BrowserRequestAssertion {
        version: 1,
        subject: identity.principal.subject().to_owned(),
        tenant_id,
        site_id,
        tenant_scope: identity
            .principal
            .has_tenant_scope(&control.config.tenant_id),
        machine: true,
        direct_apply: identity.direct_apply,
        scopes,
        roles,
        csrf_valid: true,
        expires_at: now.saturating_add(30),
    };
    AuthContext {
        principal: Some(identity.principal),
        state: AuthState::Machine,
        assertion: Some(assertion),
        direct_apply: identity.direct_apply,
        ..AuthContext::default()
    }
}

fn resolve_machine_auth(control: &ControlPlane, authorization: &str) -> AuthContext {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs());
    let valid = now.is_some_and(|now| {
        now >= control.config.credential.issued_at && now < control.config.credential.expires_at
    }) && authorization
        .strip_prefix("Bearer ")
        .filter(|token| token.len() <= super::TOKEN_BYTES_MAX)
        .is_some_and(|token| {
            memcmp::eq(
                &sha256(token.as_bytes()),
                &control.config.credential.token_digest,
            )
        });
    if valid {
        AuthContext {
            principal: Some(control.config.principal.clone()),
            state: AuthState::Machine,
            ..AuthContext::default()
        }
    } else {
        AuthContext::default()
    }
}

async fn resolve_browser_auth(
    control: &ControlPlane,
    method: &Method,
    headers: &HeaderMap,
    cookie: &str,
) -> AuthContext {
    let Some(provider) = control.oidc.as_deref() else {
        return AuthContext::default();
    };
    if cookie.len() != 64
        || !cookie
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return AuthContext::default();
    }
    let digest = sha256(cookie.as_bytes());
    let session = match control
        .catalog
        .active_management_browser_session(&digest)
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return AuthContext::default(),
        Err(_) => {
            return AuthContext {
                state: AuthState::Unavailable,
                ..AuthContext::default()
            };
        }
    };
    let Some(roles) = provider.subject_roles.get(session.subject()) else {
        return AuthContext::default();
    };
    if session.issuer() != provider.issuer {
        return AuthContext::default();
    }
    let Ok(principal) = ManagementPrincipal::new_tenant_scoped(
        session.subject(),
        roles.iter().copied(),
        [control.config.tenant_id.clone()],
    ) else {
        return AuthContext::default();
    };
    let csrf_valid = csrf_request_valid(
        method,
        headers,
        session.csrf_token(),
        &provider.console_origin,
    );
    let Some(now) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
    else {
        return AuthContext {
            state: AuthState::Unavailable,
            ..AuthContext::default()
        };
    };
    let assertion = BrowserRequestAssertion {
        version: 1,
        subject: principal.subject().to_owned(),
        tenant_id: control.config.tenant_id.as_str().to_owned(),
        site_id: control.config.site_id.as_str().to_owned(),
        tenant_scope: true,
        machine: false,
        direct_apply: false,
        scopes: vec![(
            control.config.tenant_id.as_str().to_owned(),
            control.config.site_id.as_str().to_owned(),
        )],
        roles: roles
            .iter()
            .copied()
            .map(role_name)
            .map(str::to_owned)
            .collect(),
        csrf_valid,
        expires_at: now.saturating_add(30),
    };
    AuthContext {
        principal: Some(principal),
        state: AuthState::Browser { csrf_valid },
        csrf_token: Some(session.csrf_token().to_owned()),
        session_digest: Some(digest),
        step_up_valid: session.step_up_valid(),
        session_expires_at: Some(session.expires_at()),
        idle_expires_at: Some(session.idle_expires_at()),
        last_reauthenticated_at: session.last_reauthenticated_at(),
        assertion: Some(assertion),
        direct_apply: false,
    }
}

pub(super) async fn login_handler(State(control): State<std::sync::Arc<ControlPlane>>) -> Response {
    let request_id = request_id();
    if let Some(response) = unauthenticated_rate_limit(&control, &request_id, LOGIN_ACCESS) {
        return response;
    }
    let Some(provider) = control.oidc.as_deref() else {
        return control
            .audited_error(
                &request_id,
                None,
                LOGIN_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_OIDC_UNAVAILABLE",
                "management identity is temporarily unavailable",
                true,
                "retry_later",
            )
            .into_response();
    };
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random();
    let nonce = Nonce::new_random();
    let (authorization_url, state, nonce) = provider
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            || state,
            || nonce,
        )
        .add_scope(Scope::new("openid".to_owned()))
        .add_auth_context_value(provider.required_acr.clone())
        .set_pkce_challenge(challenge)
        .url();
    let state_value = state.secret();
    if control
        .catalog
        .begin_management_oidc_transaction(
            &sha256(state_value.as_bytes()),
            verifier.secret(),
            nonce.secret(),
            None,
        )
        .await
        .is_err()
    {
        return control
            .audited_error(
                &request_id,
                None,
                LOGIN_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_OIDC_TRANSACTION_UNAVAILABLE",
                "management identity is temporarily unavailable",
                true,
                "retry_later",
            )
            .into_response();
    }
    if control
        .append_access_event(
            &request_id,
            None,
            LOGIN_ACCESS,
            None,
            "PASS",
            "CONTROL_OIDC_LOGIN_STARTED",
        )
        .is_err()
    {
        return audit_unavailable(&request_id).into_response();
    }
    let Ok(location) = HeaderValue::from_str(authorization_url.as_str()) else {
        return internal_error(&request_id).into_response();
    };
    let Ok(state_cookie) = HeaderValue::from_str(&format!(
        "{STATE_COOKIE}={state_value}; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax"
    )) else {
        return internal_error(&request_id).into_response();
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response
        .headers_mut()
        .append(header::SET_COOKIE, state_cookie);
    response
}

#[derive(Serialize)]
struct ReauthenticationStartResponse<'a> {
    schema_version: u8,
    request_id: &'a str,
    tenant_id: &'a str,
    site_id: &'a str,
    authorization_url: &'a str,
}

/// Starts a fresh MFA challenge bound to the current browser session.
pub(super) async fn reauthentication_start_handler(
    State(control): State<std::sync::Arc<ControlPlane>>,
    Extension(auth): Extension<AuthContext>,
    RawQuery(query): RawQuery,
    body: Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    let request_id = request_id();
    if let Some(response) = unauthenticated_rate_limit(&control, &request_id, REAUTH_START_ACCESS) {
        return response;
    }
    let Some(principal) = auth.principal.as_ref().filter(|_| auth.is_browser()) else {
        return auth_required_response(&control, &request_id, REAUTH_START_ACCESS, &auth);
    };
    if !can_start_step_up(
        principal,
        &control.config.tenant_id,
        &control.config.site_id,
    ) {
        return reauthentication_start_error(
            &control,
            &request_id,
            principal.subject(),
            StatusCode::FORBIDDEN,
            "CONTROL_SCOPE_DENIED",
            false,
            "verify_role",
        );
    }
    if !auth.csrf_valid() {
        return reauthentication_start_error(
            &control,
            &request_id,
            principal.subject(),
            StatusCode::FORBIDDEN,
            "CONTROL_CSRF_REQUIRED",
            false,
            "refresh_session",
        );
    }
    if query.is_some() || !body.as_ref().is_ok_and(Bytes::is_empty) {
        return reauthentication_start_error(
            &control,
            &request_id,
            principal.subject(),
            StatusCode::BAD_REQUEST,
            "CONTROL_OIDC_REAUTH_REQUEST_INVALID",
            false,
            "correct_request",
        );
    }
    let Some(session_digest) = auth.session_digest.as_ref() else {
        return internal_error(&request_id).into_response();
    };
    let Some(provider) = control.oidc.as_deref() else {
        return reauthentication_start_error(
            &control,
            &request_id,
            principal.subject(),
            StatusCode::SERVICE_UNAVAILABLE,
            "CONTROL_OIDC_UNAVAILABLE",
            true,
            "retry_later",
        );
    };
    match control
        .catalog
        .active_management_browser_session(session_digest)
        .await
    {
        Ok(Some(session))
            if session.issuer() == provider.issuer && session.subject() == principal.subject() => {}
        Ok(Some(_) | None) => {
            return reauthentication_start_error(
                &control,
                &request_id,
                principal.subject(),
                StatusCode::UNAUTHORIZED,
                "CONTROL_SESSION_REVOKED",
                false,
                "authenticate",
            );
        }
        Err(_) => {
            return reauthentication_start_error(
                &control,
                &request_id,
                principal.subject(),
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_SESSION_UNAVAILABLE",
                true,
                "retry_later",
            );
        }
    }
    begin_reauthentication(&control, &request_id, principal, session_digest, provider).await
}

fn can_start_step_up(
    principal: &ManagementPrincipal,
    tenant_id: &TenantId,
    site_id: &SiteId,
) -> bool {
    [
        ManagementRole::SensitiveEvidenceReader,
        ManagementRole::PolicyApprover,
    ]
    .into_iter()
    .any(|role| principal.authorizes_site(role, tenant_id, site_id))
}

fn reauthentication_start_error(
    control: &ControlPlane,
    request_id: &str,
    subject: &str,
    status: StatusCode,
    reason: &'static str,
    retryable: bool,
    next_action: &'static str,
) -> Response {
    control
        .audited_error(
            request_id,
            Some(subject),
            REAUTH_START_ACCESS,
            None,
            status,
            reason,
            "sensitive operation reauthentication could not be started",
            retryable,
            next_action,
        )
        .into_response()
}

async fn begin_reauthentication(
    control: &ControlPlane,
    request_id: &str,
    principal: &ManagementPrincipal,
    session_digest: &[u8; 32],
    provider: &OidcProvider,
) -> Response {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random();
    let nonce = Nonce::new_random();
    let (authorization_url, state, nonce) = provider
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            || state,
            || nonce,
        )
        .add_scope(Scope::new("openid".to_owned()))
        .add_auth_context_value(provider.required_acr.clone())
        .set_max_age(std::time::Duration::ZERO)
        .add_prompt(CoreAuthPrompt::Login)
        .set_pkce_challenge(challenge)
        .url();
    let state_value = state.secret();
    if control
        .catalog
        .begin_management_oidc_transaction(
            &sha256(state_value.as_bytes()),
            verifier.secret(),
            nonce.secret(),
            Some(session_digest),
        )
        .await
        .is_err()
    {
        return reauthentication_start_error(
            control,
            request_id,
            principal.subject(),
            StatusCode::SERVICE_UNAVAILABLE,
            "CONTROL_OIDC_TRANSACTION_UNAVAILABLE",
            true,
            "retry_later",
        );
    }
    if control
        .append_access_event(
            request_id,
            Some(principal.subject()),
            REAUTH_START_ACCESS,
            None,
            "PASS",
            "CONTROL_OIDC_REAUTH_STARTED",
        )
        .is_err()
    {
        return audit_unavailable(request_id).into_response();
    }
    let Ok(state_cookie) = HeaderValue::from_str(&format!(
        "{STATE_COOKIE}={state_value}; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax"
    )) else {
        return internal_error(request_id).into_response();
    };
    let mut response = Json(ReauthenticationStartResponse {
        schema_version: 3,
        request_id,
        tenant_id: control.config.tenant_id.as_str(),
        site_id: control.config.site_id.as_str(),
        authorization_url: authorization_url.as_str(),
    })
    .into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, state_cookie);
    response
}

#[derive(Default)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    error_uri: Option<String>,
    issuer: Option<String>,
    session_state: Option<String>,
}

fn parse_callback_query(raw: Option<&str>) -> Result<CallbackQuery, ()> {
    let raw = raw.ok_or(())?;
    if raw.len() > CALLBACK_QUERY_BYTES_MAX {
        return Err(());
    }
    let mut result = CallbackQuery::default();
    let mut seen = std::collections::BTreeSet::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !seen.insert(key.to_string())
            || value.len() > 2_048
            || value.chars().any(char::is_control)
        {
            return Err(());
        }
        match key.as_ref() {
            "code" => result.code = Some(value.into_owned()),
            "state" => result.state = Some(value.into_owned()),
            "error" => result.error = Some(value.into_owned()),
            "error_description" => result.error_description = Some(value.into_owned()),
            "error_uri" => result.error_uri = Some(value.into_owned()),
            "iss" => result.issuer = Some(value.into_owned()),
            // Keycloak emits the optional OpenID Session Management value. It
            // is not used for authorization, but is part of a valid callback.
            "session_state" => result.session_state = Some(value.into_owned()),
            _ => return Err(()),
        }
    }
    if result
        .state
        .as_ref()
        .is_none_or(|state| state.is_empty() || state.len() > STATE_BYTES_MAX)
        || result.code.is_some() == result.error.is_some()
        || result.error.is_none()
            && (result.error_description.is_some() || result.error_uri.is_some())
    {
        return Err(());
    }
    Ok(result)
}

async fn verify_oidc_subject(
    provider: &OidcProvider,
    code: String,
    verifier: String,
    nonce: String,
) -> Result<VerifiedOidcIdentity, (StatusCode, &'static str)> {
    let exchange = provider
        .client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| (StatusCode::UNAUTHORIZED, "CONTROL_OIDC_TOKEN_REJECTED"))?;
    let token = exchange
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&provider.http)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "CONTROL_OIDC_TOKEN_REJECTED"))?;
    let id_token = token
        .id_token()
        .ok_or((StatusCode::UNAUTHORIZED, "CONTROL_OIDC_ID_TOKEN_MISSING"))?;
    let verifier = provider.client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &Nonce::new(nonce))
        .map_err(|_| (StatusCode::UNAUTHORIZED, "CONTROL_OIDC_ID_TOKEN_REJECTED"))?;
    if claims.issuer().as_str() != provider.issuer
        || claims
            .auth_context_ref()
            .is_none_or(|acr| acr.as_ref() != provider.required_acr.as_ref())
    {
        return Err((StatusCode::UNAUTHORIZED, "CONTROL_OIDC_MFA_REQUIRED"));
    }
    if let Some(expected) = claims.access_token_hash() {
        let signing_algorithm = id_token
            .signing_alg()
            .map_err(|_| access_token_hash_error())?;
        let signing_key = id_token
            .signing_key(&verifier)
            .map_err(|_| access_token_hash_error())?;
        let actual =
            AccessTokenHash::from_token(token.access_token(), signing_algorithm, signing_key)
                .map_err(|_| access_token_hash_error())?;
        if expected != &actual {
            return Err(access_token_hash_error());
        }
    }
    let subject = claims.subject().as_str();
    if !provider.subject_roles.contains_key(subject) {
        return Err((
            StatusCode::FORBIDDEN,
            "CONTROL_OIDC_SUBJECT_NOT_PROVISIONED",
        ));
    }
    Ok(VerifiedOidcIdentity {
        subject: subject.to_owned(),
        auth_time_unix: claims.auth_time().as_ref().map(chrono::DateTime::timestamp),
    })
}

struct VerifiedOidcIdentity {
    subject: String,
    auth_time_unix: Option<i64>,
}

fn auth_time_is_recent(auth_time_unix: Option<i64>, now_unix: u64) -> bool {
    auth_time_unix
        .and_then(|value| u64::try_from(value).ok())
        .is_some_and(|auth_time| {
            auth_time <= now_unix.saturating_add(30)
                && now_unix.saturating_sub(auth_time) <= STEP_UP_AUTH_TIME_MAX_AGE_SECONDS
        })
}

fn finish_step_up_callback(provider: &OidcProvider, request_id: &str) -> Response {
    let Some(location) = HeaderValue::from_str(&format!("{}/", provider.console_origin)).ok()
    else {
        return internal_error(request_id).into_response();
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-xshield-oidc-state=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
        ),
    );
    response
}

async fn complete_step_up_callback(
    control: &ControlPlane,
    provider: &OidcProvider,
    request_id: &str,
    identity: VerifiedOidcIdentity,
    session_digest: &[u8; 32],
) -> Response {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs());
    if !now.is_some_and(|now| auth_time_is_recent(identity.auth_time_unix, now)) {
        return control
            .audited_error(
                request_id,
                None,
                CALLBACK_ACCESS,
                None,
                StatusCode::UNAUTHORIZED,
                "CONTROL_OIDC_AUTH_TIME_STALE",
                "management sign-in could not be completed",
                false,
                "sign_in_again",
            )
            .into_response();
    }
    if control
        .append_access_event(
            request_id,
            Some(&identity.subject),
            REAUTH_CALLBACK_ACCESS,
            None,
            "PASS",
            "CONTROL_OIDC_REAUTH_VERIFIED",
        )
        .is_err()
    {
        return audit_unavailable(request_id).into_response();
    }
    match control
        .catalog
        .reauthenticate_management_browser_session(
            session_digest,
            &provider.issuer,
            &identity.subject,
        )
        .await
    {
        Ok(true) => finish_step_up_callback(provider, request_id),
        Ok(false) => control
            .audited_error(
                request_id,
                None,
                CALLBACK_ACCESS,
                None,
                StatusCode::UNAUTHORIZED,
                "CONTROL_OIDC_REAUTH_SESSION_INVALID",
                "management sign-in could not be completed",
                false,
                "sign_in_again",
            )
            .into_response(),
        Err(_) => control
            .audited_error(
                request_id,
                Some(&identity.subject),
                REAUTH_CALLBACK_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_SESSION_UNAVAILABLE",
                "management session is temporarily unavailable",
                true,
                "retry_later",
            )
            .into_response(),
    }
}

fn access_token_hash_error() -> (StatusCode, &'static str) {
    (
        StatusCode::UNAUTHORIZED,
        "CONTROL_OIDC_ACCESS_TOKEN_HASH_INVALID",
    )
}

async fn finish_oidc_login(
    control: &ControlPlane,
    provider: &OidcProvider,
    request_id: &str,
    subject: &str,
) -> Response {
    let unavailable = |reason| {
        control
            .audited_error(
                request_id,
                Some(subject),
                CALLBACK_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                reason,
                "management identity is temporarily unavailable",
                true,
                "retry_later",
            )
            .into_response()
    };
    let mut session_token = [0_u8; 32];
    let mut csrf_bytes = [0_u8; 32];
    if rand_bytes(&mut session_token).is_err() || rand_bytes(&mut csrf_bytes).is_err() {
        return unavailable("CONTROL_ENTROPY_UNAVAILABLE");
    }
    let session_token = lower_hex(&session_token);
    let csrf_token = lower_hex(&csrf_bytes);
    let session_digest = sha256(session_token.as_bytes());
    if control
        .catalog
        .create_management_browser_session(&session_digest, &provider.issuer, subject, &csrf_token)
        .await
        .is_err()
    {
        return unavailable("CONTROL_SESSION_UNAVAILABLE");
    }
    if control
        .append_access_event(
            request_id,
            Some(subject),
            CALLBACK_ACCESS,
            None,
            "PASS",
            "CONTROL_OIDC_LOGIN_COMPLETED",
        )
        .is_err()
    {
        let _ = control
            .catalog
            .revoke_management_browser_session(&session_digest)
            .await;
        return audit_unavailable(request_id).into_response();
    }
    let Ok(session_cookie) = HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={session_token}; Path=/; Max-Age={BROWSER_SESSION_LIFETIME_SECONDS}; Secure; HttpOnly; SameSite=Lax"
    )) else {
        let _ = control
            .catalog
            .revoke_management_browser_session(&session_digest)
            .await;
        return internal_error(request_id).into_response();
    };
    let Some(location) = HeaderValue::from_str(&format!("{}/", provider.console_origin)).ok()
    else {
        let _ = control
            .catalog
            .revoke_management_browser_session(&session_digest)
            .await;
        return internal_error(request_id).into_response();
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response
        .headers_mut()
        .append(header::SET_COOKIE, session_cookie);
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-xshield-oidc-state=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
        ),
    );
    response
}

pub(super) async fn callback_handler(
    State(control): State<std::sync::Arc<ControlPlane>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let request_id = request_id();
    if let Some(response) = unauthenticated_rate_limit(&control, &request_id, CALLBACK_ACCESS) {
        return response;
    }
    let fail = |status, reason: &'static str| {
        control
            .audited_error(
                &request_id,
                None,
                CALLBACK_ACCESS,
                None,
                status,
                reason,
                "management sign-in could not be completed",
                false,
                "sign_in_again",
            )
            .into_response()
    };
    let Some(provider) = control.oidc.as_deref() else {
        return control
            .audited_error(
                &request_id,
                None,
                CALLBACK_ACCESS,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_OIDC_UNAVAILABLE",
                "management identity is temporarily unavailable",
                true,
                "retry_later",
            )
            .into_response();
    };
    let Ok(query) = parse_callback_query(raw_query.as_deref()) else {
        return fail(StatusCode::BAD_REQUEST, "CONTROL_OIDC_CALLBACK_INVALID");
    };
    if query.error.is_some() {
        return fail(StatusCode::UNAUTHORIZED, "CONTROL_OIDC_LOGIN_DENIED");
    }
    if query
        .issuer
        .as_ref()
        .is_some_and(|issuer| issuer != &provider.issuer)
    {
        return fail(StatusCode::UNAUTHORIZED, "CONTROL_OIDC_ISSUER_MISMATCH");
    }
    let Some(state_cookie) = cookie_value(&headers, STATE_COOKIE) else {
        return fail(StatusCode::UNAUTHORIZED, "CONTROL_OIDC_STATE_INVALID");
    };
    let Some(state) = query.state.as_deref() else {
        return fail(StatusCode::BAD_REQUEST, "CONTROL_OIDC_CALLBACK_INVALID");
    };
    if !memcmp::eq(state.as_bytes(), state_cookie.as_bytes()) {
        return fail(StatusCode::UNAUTHORIZED, "CONTROL_OIDC_STATE_INVALID");
    }
    let transaction = match control
        .catalog
        .consume_management_oidc_transaction(&sha256(state.as_bytes()))
        .await
    {
        Ok(Some(transaction)) => transaction,
        Ok(None) => return fail(StatusCode::UNAUTHORIZED, "CONTROL_OIDC_STATE_EXPIRED"),
        Err(_) => {
            return fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "CONTROL_OIDC_TRANSACTION_UNAVAILABLE",
            );
        }
    };
    let Some(code) = query.code else {
        return fail(StatusCode::BAD_REQUEST, "CONTROL_OIDC_CALLBACK_INVALID");
    };
    if code.is_empty() || code.len() > 2_048 {
        return fail(StatusCode::BAD_REQUEST, "CONTROL_OIDC_CALLBACK_INVALID");
    }
    let identity = match verify_oidc_subject(
        provider,
        code,
        transaction.pkce_verifier().to_owned(),
        transaction.nonce().to_owned(),
    )
    .await
    {
        Ok(subject) => subject,
        Err((status, reason)) => return fail(status, reason),
    };
    let Some(session_digest) = transaction.session_digest() else {
        return finish_oidc_login(&control, provider, &request_id, &identity.subject).await;
    };
    let Ok(session_digest) = <[u8; 32]>::try_from(session_digest) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "CONTROL_OIDC_TRANSACTION_UNAVAILABLE",
        );
    };
    complete_step_up_callback(&control, provider, &request_id, identity, &session_digest).await
}

#[derive(Serialize)]
struct SessionResponse<'a> {
    subject: &'a str,
    tenant_id: &'a str,
    site_id: &'a str,
    csrf_token: &'a str,
    roles: &'a [String],
    session_expires_at: Option<String>,
    idle_expires_at: Option<String>,
    last_reauthenticated_at: Option<String>,
    step_up_valid: bool,
}

pub(super) async fn session_handler(
    State(control): State<std::sync::Arc<ControlPlane>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let request_id = request_id();
    let Some(principal) = auth.principal.as_ref().filter(|_| auth.is_browser()) else {
        if let Some(response) =
            unauthenticated_rate_limit(&control, &request_id, SESSION_READ_ACCESS)
        {
            return response;
        }
        return auth_required_response(&control, &request_id, SESSION_READ_ACCESS, &auth);
    };
    let Some(csrf_token) = auth.csrf_token.as_deref() else {
        return internal_error(&request_id).into_response();
    };
    let Some(roles) = auth
        .assertion
        .as_ref()
        .map(|assertion| assertion.roles.as_slice())
    else {
        return internal_error(&request_id).into_response();
    };
    if control
        .append_access_event(
            &request_id,
            Some(principal.subject()),
            SESSION_READ_ACCESS,
            None,
            "PASS",
            "CONTROL_BROWSER_SESSION_READ",
        )
        .is_err()
    {
        return audit_unavailable(&request_id).into_response();
    }
    Json(SessionResponse {
        subject: principal.subject(),
        tenant_id: control.config.tenant_id.as_str(),
        site_id: control.config.site_id.as_str(),
        csrf_token,
        roles,
        session_expires_at: auth
            .session_expires_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
        idle_expires_at: auth
            .idle_expires_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
        last_reauthenticated_at: auth
            .last_reauthenticated_at
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true)),
        step_up_valid: auth.step_up_valid,
    })
    .into_response()
}

pub(super) async fn logout_handler(
    State(control): State<std::sync::Arc<ControlPlane>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let request_id = request_id();
    let Some(principal) = auth.principal.as_ref().filter(|_| auth.is_browser()) else {
        if let Some(response) =
            unauthenticated_rate_limit(&control, &request_id, SESSION_LOGOUT_ACCESS)
        {
            return response;
        }
        return auth_required_response(&control, &request_id, SESSION_LOGOUT_ACCESS, &auth);
    };
    if !auth.csrf_valid() {
        return control
            .audited_error(
                &request_id,
                Some(principal.subject()),
                SESSION_LOGOUT_ACCESS,
                None,
                StatusCode::FORBIDDEN,
                "CONTROL_CSRF_REQUIRED",
                "management operation forbidden",
                false,
                "refresh_session",
            )
            .into_response();
    }
    let Some(digest) = auth.session_digest.as_ref() else {
        return internal_error(&request_id).into_response();
    };
    match control
        .catalog
        .revoke_management_browser_session(digest)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return control
                .audited_error(
                    &request_id,
                    Some(principal.subject()),
                    SESSION_LOGOUT_ACCESS,
                    None,
                    StatusCode::UNAUTHORIZED,
                    "CONTROL_SESSION_REVOKED",
                    "management authentication required",
                    false,
                    "authenticate",
                )
                .into_response();
        }
        Err(_) => {
            return control
                .audited_error(
                    &request_id,
                    Some(principal.subject()),
                    SESSION_LOGOUT_ACCESS,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_SESSION_UNAVAILABLE",
                    "management service unavailable",
                    true,
                    "retry_later",
                )
                .into_response();
        }
    }
    if control
        .append_access_event(
            &request_id,
            Some(principal.subject()),
            SESSION_LOGOUT_ACCESS,
            None,
            "PASS",
            "CONTROL_BROWSER_SESSION_REVOKED",
        )
        .is_err()
    {
        return audit_unavailable(&request_id).into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(cookie) = HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
    )) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn request_id() -> String {
    format!("req_{}", uuid::Uuid::now_v7())
}

fn unauthenticated_rate_limit(
    control: &ControlPlane,
    request_id: &str,
    action: AccessAction,
) -> Option<Response> {
    match control.take_unauthenticated_rate_budget() {
        Some(true) => None,
        Some(false) => Some(
            super::api_error(
                request_id,
                StatusCode::TOO_MANY_REQUESTS,
                "CONTROL_RATE_LIMITED",
                "management request rate exceeded",
                true,
                "retry_later",
            )
            .into_response(),
        ),
        None => Some(
            control
                .audited_error(
                    request_id,
                    None,
                    action,
                    None,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CONTROL_RATE_UNAVAILABLE",
                    "management service unavailable",
                    true,
                    "retry_later",
                )
                .into_response(),
        ),
    }
}

fn auth_required_response(
    control: &ControlPlane,
    request_id: &str,
    action: AccessAction,
    auth: &AuthContext,
) -> Response {
    let unavailable = auth.is_unavailable();
    control
        .audited_error(
            request_id,
            None,
            action,
            None,
            if unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNAUTHORIZED
            },
            if unavailable {
                "CONTROL_SESSION_UNAVAILABLE"
            } else {
                "CONTROL_AUTH_REQUIRED"
            },
            "management authentication required",
            unavailable,
            if unavailable {
                "retry_later"
            } else {
                "authenticate"
            },
        )
        .into_response()
}

fn csrf_request_valid(
    method: &Method,
    headers: &HeaderMap,
    expected_token: &str,
    expected_origin: &str,
) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    single_header(headers, header::ORIGIN.as_str()).is_some_and(|origin| {
        origin == expected_origin
            && single_header(headers, CSRF_HEADER)
                .is_some_and(|value| memcmp::eq(value.as_bytes(), expected_token.as_bytes()))
    })
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let values = headers.get_all(header::COOKIE).iter().collect::<Vec<_>>();
    if values.is_empty() || values.len() > 4 {
        return None;
    }
    let mut found = None;
    for header in values {
        let header = header.to_str().ok()?;
        if header.len() > 4_096 {
            return None;
        }
        for cookie in header.split(';') {
            let (cookie_name, value) = cookie.trim().split_once('=')?;
            if cookie_name.trim() == name {
                if found.is_some() || value.is_empty() || value.contains('=') {
                    return None;
                }
                found = Some(value.trim().to_owned());
            }
        }
    }
    found
}

fn cookie_name_present(headers: &HeaderMap, name: &str) -> bool {
    headers.get_all(header::COOKIE).iter().any(|header| {
        header.to_str().ok().is_some_and(|header| {
            header.split(';').any(|cookie| {
                cookie
                    .split_once('=')
                    .is_some_and(|(cookie_name, _)| cookie_name.trim() == name)
            })
        })
    })
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserRequestAssertion, ManagementRole, STEP_UP_AUTH_TIME_MAX_AGE_SECONDS,
        auth_time_is_recent, can_start_step_up, cookie_value, csrf_request_valid,
        endpoint_is_secure, lower_hex, parse_callback_query, secure_url, sign_request_assertion,
        verify_request_assertion,
    };
    use axum::http::{HeaderMap, Method, header};
    use std::time::{SystemTime, UNIX_EPOCH};
    use xshield_core::domain::{SiteId, TenantId};

    #[test]
    fn policy_approver_can_start_independent_step_up() {
        let tenant = TenantId::parse("tenant_a").unwrap();
        let site = SiteId::parse("site_a").unwrap();
        let approver = xshield_core::admin::ManagementPrincipal::new_tenant_scoped(
            "approver",
            [ManagementRole::PolicyApprover],
            [tenant.clone()],
        )
        .unwrap();
        assert!(can_start_step_up(&approver, &tenant, &site));
        let observer = xshield_core::admin::ManagementPrincipal::new_tenant_scoped(
            "observer",
            [ManagementRole::Observer],
            [tenant.clone()],
        )
        .unwrap();
        assert!(!can_start_step_up(&observer, &tenant, &site));
    }

    #[test]
    fn callback_parser_rejects_duplicates_unknown_fields_and_mixed_results() {
        assert!(parse_callback_query(Some("code=one&state=two")).is_ok());
        assert!(parse_callback_query(Some("error=access_denied&state=two")).is_ok());
        assert!(parse_callback_query(Some("code=one&code=two&state=s")).is_err());
        assert!(parse_callback_query(Some("code=one&error=bad&state=s")).is_err());
        assert!(parse_callback_query(Some("code=one&state=s&next=https%3A%2F%2Fevil")).is_err());
        assert!(parse_callback_query(Some("code=one&state=s&iss=https%3A%2F%2Fissuer")).is_ok());
        assert!(
            parse_callback_query(Some(
                "code=one&state=s&iss=https%3A%2F%2Fissuer&session_state=provider-session"
            ))
            .is_ok()
        );
        assert!(
            parse_callback_query(Some("error=denied&error_description=policy&state=s")).is_ok()
        );
        assert!(parse_callback_query(Some("code=one&error_description=ignored&state=s")).is_err());
    }

    #[test]
    fn step_up_requires_a_recent_non_future_oidc_auth_time() {
        let now = 1_800_000_000_u64;
        assert!(auth_time_is_recent(Some(i64::try_from(now).unwrap()), now));
        assert!(auth_time_is_recent(
            Some(i64::try_from(now - STEP_UP_AUTH_TIME_MAX_AGE_SECONDS).unwrap()),
            now,
        ));
        assert!(!auth_time_is_recent(
            Some(i64::try_from(now - STEP_UP_AUTH_TIME_MAX_AGE_SECONDS - 1).unwrap()),
            now,
        ));
        assert!(auth_time_is_recent(
            Some(i64::try_from(now + 30).unwrap()),
            now,
        ));
        assert!(!auth_time_is_recent(
            Some(i64::try_from(now + 31).unwrap()),
            now,
        ));
        assert!(!auth_time_is_recent(None, now));
        assert!(!auth_time_is_recent(Some(-1), now));
    }

    #[test]
    fn oidc_urls_require_tls_except_for_loopback_development() {
        assert!(secure_url("https://idp.example", false).is_ok());
        assert!(secure_url("http://127.0.0.1:9000", false).is_ok());
        assert!(secure_url("http://idp.example", false).is_err());
        assert!(secure_url("https://user:pass@idp.example", false).is_err());
        assert!(endpoint_is_secure("https://idp.example/token", false));
        assert!(!endpoint_is_secure("http://127.0.0.1/token", false));
        assert!(endpoint_is_secure("http://127.0.0.1/token", true));
        assert!(!endpoint_is_secure("https://127.0.0.1/token", false));
        assert!(endpoint_is_secure("https://127.0.0.1/token", true));
        assert!(!endpoint_is_secure("http://internal.example/token", true));
    }

    #[test]
    fn browser_assertions_are_short_lived_signed_and_role_scoped() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let assertion = BrowserRequestAssertion {
            version: 1,
            subject: "human-1".to_owned(),
            tenant_id: "tenant_a".to_owned(),
            site_id: "site_a".to_owned(),
            tenant_scope: false,
            machine: false,
            direct_apply: false,
            scopes: vec![("tenant_a".to_owned(), "site_a".to_owned())],
            roles: vec!["observer".to_owned()],
            csrf_valid: false,
            expires_at: now + 30,
        };
        let key = [0x5a; 32];
        let signed = sign_request_assertion(&assertion, &key).unwrap();
        let identity = verify_request_assertion(&signed, &key).unwrap();
        assert!(identity.browser);
        assert!(!identity.csrf_valid);
        assert!(identity.principal.authorizes(
            ManagementRole::Observer,
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
        ));
        assert!(!identity.principal.authorizes(
            ManagementRole::Investigator,
            &TenantId::parse("tenant_a").unwrap(),
            &SiteId::parse("site_a").unwrap(),
        ));
        assert!(verify_request_assertion(&signed, &[0xa5; 32]).is_none());
        let mut altered = signed.into_bytes();
        if let Some(last) = altered.last_mut() {
            *last = if *last == b'0' { b'1' } else { b'0' };
        }
        let altered = String::from_utf8(altered).unwrap();
        assert!(verify_request_assertion(&altered, &key).is_none());
        assert_eq!(lower_hex(b"\x00\xff"), "00ff");
    }

    #[test]
    fn cookie_lookup_rejects_duplicate_session_cookie_names() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "theme=light; __Host-xshield-session=abc".parse().unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, "__Host-xshield-session").as_deref(),
            Some("abc")
        );
        headers.insert(
            header::COOKIE,
            "__Host-xshield-session=one; __Host-xshield-session=two"
                .parse()
                .unwrap(),
        );
        assert!(cookie_value(&headers, "__Host-xshield-session").is_none());
    }

    #[test]
    fn browser_writes_require_exact_origin_and_csrf_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://console.example".parse().unwrap());
        headers.insert("x-xshield-csrf", "a".repeat(64).parse().unwrap());
        assert!(csrf_request_valid(
            &Method::POST,
            &headers,
            &"a".repeat(64),
            "https://console.example",
        ));
        assert!(!csrf_request_valid(
            &Method::POST,
            &headers,
            &"b".repeat(64),
            "https://console.example",
        ));
        assert!(!csrf_request_valid(
            &Method::POST,
            &headers,
            &"a".repeat(64),
            "https://attacker.example",
        ));
        assert!(csrf_request_valid(
            &Method::GET,
            &HeaderMap::new(),
            "unused",
            "https://console.example",
        ));
        headers.append("x-xshield-csrf", "a".repeat(64).parse().unwrap());
        assert!(!csrf_request_valid(
            &Method::POST,
            &headers,
            &"a".repeat(64),
            "https://console.example",
        ));
    }
}
