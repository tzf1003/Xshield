//! Strongly typed management API client used by Agent site tools.
#![allow(clippy::missing_errors_doc)]

use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;
use xshield_core::site::SitePolicyConfig;
use zeroize::Zeroizing;

/// Errors returned by the bounded Agent management client.
#[derive(Debug)]
pub enum AgentClientError {
    /// Transport or response decoding failure.
    Http(reqwest::Error),
    /// An internal endpoint path could not be joined to the validated origin.
    InvalidPath,
}

impl From<reqwest::Error> for AgentClientError {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

/// A validated site configuration submitted by an Agent.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSiteConfig {
    /// Stable site identifier.
    pub site_id: String,
    /// Display label.
    pub display_name: String,
    /// Public HTTPS origin.
    pub public_origin: String,
    /// Validated upstream address.
    pub upstream_address: String,
    /// Upstream SNI name.
    pub upstream_server_name: String,
    /// Whether upstream TLS is enabled.
    pub upstream_tls: bool,
    /// Reserved listener port.
    pub listen_port: u16,
    /// Entry route path.
    pub entry_path: String,
    /// Security entry mode.
    pub security_entry: String,
    /// Whether the optional sensor is enabled.
    #[serde(default)]
    pub sensor_enabled: bool,
    /// Expected policy revision.
    pub policy_revision: String,
    /// Desired lifecycle state.
    #[serde(default = "default_site_status")]
    pub status: String,
    /// Typed policy document.
    pub policy: SitePolicyConfig,
}

#[allow(dead_code)]
fn default_site_status() -> String {
    "active".to_owned()
}

/// Stable result envelope returned by Agent tool calls.
#[derive(Clone, Debug, Deserialize)]
pub struct AgentToolResult {
    /// Correlation identifier.
    pub request_id: String,
    /// Current revision when supplied by the server.
    pub revision: Option<String>,
    /// Configuration digest when supplied by the server.
    pub config_digest: Option<String>,
    /// Apply lifecycle state.
    pub apply_state: Option<String>,
    /// Stable refusal or failure code.
    pub reason_code: Option<String>,
    /// Server response details.
    #[serde(flatten)]
    pub details: serde_json::Map<String, serde_json::Value>,
}

/// Bounded client for Agent management operations.
pub struct AgentSiteClient {
    base_url: Url,
    api_key: Zeroizing<String>,
    http: Client,
}

impl AgentSiteClient {
    /// Creates a client restricted to a loopback or HTTPS control origin.
    pub fn new(base_url: &str, api_key: String) -> Result<Self, &'static str> {
        let base_url = Url::parse(base_url).map_err(|_| "invalid control URL")?;
        if !matches!(base_url.scheme(), "https" | "http")
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || (base_url.scheme() == "http"
                && !base_url
                    .host_str()
                    .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "[::1]")))
        {
            return Err("invalid control URL");
        }
        if !api_key.starts_with("xsk_") || api_key.len() > 256 {
            return Err("invalid API key");
        }
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "client unavailable")?;
        Ok(Self {
            base_url,
            api_key: Zeroizing::new(api_key),
            http,
        })
    }

    /// Lists sites visible to the key.
    pub async fn list_sites(
        &self,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request_no_body(
            Method::GET,
            "/control/v1/sites",
            agent_run_id,
            idempotency_key,
        )
        .await
    }
    /// Gets one site.
    pub async fn get_site(
        &self,
        site_id: &str,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request_no_body(
            Method::GET,
            &format!("/control/v1/sites/{site_id}"),
            agent_run_id,
            idempotency_key,
        )
        .await
    }
    /// Creates one site.
    pub async fn create_site(
        &self,
        config: &AgentSiteConfig,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request(
            Method::POST,
            "/control/v1/sites",
            Some(config),
            agent_run_id,
            idempotency_key,
        )
        .await
    }
    /// Updates one site configuration.
    pub async fn update_site_config(
        &self,
        config: &AgentSiteConfig,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request(
            Method::PUT,
            &format!("/control/v1/sites/{}/config", config.site_id),
            Some(config),
            agent_run_id,
            idempotency_key,
        )
        .await
    }
    /// Validates one site configuration.
    pub async fn validate_site(
        &self,
        site_id: &str,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request_no_body(
            Method::POST,
            &format!("/control/v1/sites/{site_id}/validate"),
            agent_run_id,
            idempotency_key,
        )
        .await
    }
    /// Applies one site configuration directly when the key has that capability.
    pub async fn apply_site_config(
        &self,
        site_id: &str,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request_no_body(
            Method::POST,
            &format!("/control/v1/sites/{site_id}/apply"),
            agent_run_id,
            idempotency_key,
        )
        .await
    }
    /// Reads site health.
    pub async fn get_site_health(
        &self,
        site_id: &str,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request_no_body(
            Method::GET,
            &format!("/control/v1/sites/{site_id}/health"),
            agent_run_id,
            idempotency_key,
        )
        .await
    }
    /// Rolls back a site.
    pub async fn rollback_site(
        &self,
        site_id: &str,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request_no_body(
            Method::POST,
            &format!("/control/v1/sites/{site_id}/rollback"),
            agent_run_id,
            idempotency_key,
        )
        .await
    }

    async fn request<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&T>,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        let Some(url) = self.base_url.join(path.trim_start_matches('/')).ok() else {
            return Err(AgentClientError::InvalidPath);
        };
        let mut request = self
            .http
            .request(method, url)
            .header("X-Xshield-API-Key", &*self.api_key)
            .header("X-Xshield-Agent-Run-Id", agent_run_id)
            .header("Idempotency-Key", idempotency_key);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await?;
        let status = response.status();
        let value = response.json::<AgentToolResult>().await?;
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Ok(value);
        }
        Ok(value)
    }

    async fn request_no_body(
        &self,
        method: Method,
        path: &str,
        agent_run_id: &str,
        idempotency_key: &str,
    ) -> Result<AgentToolResult, AgentClientError> {
        self.request::<serde_json::Value>(method, path, None, agent_run_id, idempotency_key)
            .await
    }
}
