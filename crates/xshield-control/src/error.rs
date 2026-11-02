//! Error responses of the control API (docs/07-console-architecture.md section
//! 7.9.1): a stable code, plus the field or the current version when the error
//! is about one of them. Causes of internal errors go to the log, never to the
//! response.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use xshield_core::context::ConfigError;
use xshield_postgres::{
    decision_log_store::DecisionLogStoreError, partitions::PartitionError,
    site_spec_store::SiteSpecStoreError,
};

/// The result of a control API handler.
pub type ApiResult<T> = Result<T, ApiError>;

/// One failed request: its status, its stable code and what it is about.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    field: Option<String>,
    current_version: Option<i64>,
}

impl ApiError {
    /// An error with a status and a stable code.
    #[must_use]
    pub fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            field: None,
            current_version: None,
        }
    }

    /// Names the query parameter or body field the error is about.
    #[must_use]
    pub fn in_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    /// Adds the version the site has now, for a version conflict.
    #[must_use]
    pub fn at_version(mut self, version: i64) -> Self {
        self.current_version = Some(version);
        self
    }

    /// A 400 for a query parameter the API does not accept.
    #[must_use]
    pub fn invalid_filter(field: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "INVALID_FILTER").in_field(field)
    }

    /// A 400 for a request body that is not the JSON the endpoint expects.
    #[must_use]
    pub fn invalid_body(field: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "INVALID_BODY").in_field(field)
    }

    /// The HTTP status this error is sent with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The body a configuration check reports for this error: `valid: false`
    /// with the code and the field, rather than an HTTP error.
    #[must_use]
    pub fn validation_report(&self) -> ValidationBody {
        ValidationBody {
            valid: false,
            error: Some(self.code.to_owned()),
            field: self.field.clone(),
        }
    }

    /// A 500 that names no cause to the client. The cause goes to the log.
    #[must_use]
    pub fn internal(context: &str, cause: impl std::fmt::Display) -> Self {
        eprintln!("xshield-control: {context} failed: {cause}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL")
    }
}

/// The verdict of `POST /api/sites/validate` (docs/07 section 7.9.2): `valid` alone
/// for a configuration the gateway would accept, or the error code and the field of
/// one it would refuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationBody {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl ValidationBody {
    /// The verdict for a configuration the gateway would accept.
    #[must_use]
    pub fn accepted() -> Self {
        Self {
            valid: true,
            error: None,
            field: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = Map::new();
        body.insert("error".to_owned(), Value::from(self.code));
        if let Some(field) = self.field {
            body.insert("field".to_owned(), Value::from(field));
        }
        if let Some(version) = self.current_version {
            body.insert("current_version".to_owned(), Value::from(version));
        }
        (self.status, Json(Value::Object(body))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal("database", error)
    }
}

impl From<DecisionLogStoreError> for ApiError {
    fn from(error: DecisionLogStoreError) -> Self {
        Self::internal("decision log", error)
    }
}

impl From<PartitionError> for ApiError {
    fn from(error: PartitionError) -> Self {
        Self::internal("partition maintenance", error)
    }
}

impl From<SiteSpecStoreError> for ApiError {
    fn from(error: SiteSpecStoreError) -> Self {
        match error {
            SiteSpecStoreError::AlreadyExists => Self::new(StatusCode::CONFLICT, "SITE_EXISTS"),
            other => Self::internal("site store", other),
        }
    }
}

impl From<ConfigError> for ApiError {
    /// A configuration error keeps its `SITE_CONFIG_*` code and names the
    /// top-level section it is about, so the console can point at it.
    fn from(error: ConfigError) -> Self {
        let (code, field) = match error {
            ConfigError::Malformed => ("SITE_CONFIG_MALFORMED", None),
            ConfigError::Name => ("SITE_CONFIG_NAME_INVALID", Some("name")),
            ConfigError::Hosts => ("SITE_CONFIG_HOSTS_INVALID", Some("hosts")),
            ConfigError::Origin => ("SITE_CONFIG_ORIGIN_INVALID", Some("origin")),
            ConfigError::Session => ("SITE_CONFIG_SESSION_INVALID", Some("session")),
            ConfigError::Entries => ("SITE_CONFIG_ENTRIES_INVALID", Some("entries")),
            ConfigError::Bypass => ("SITE_CONFIG_BYPASS_INVALID", Some("bypass")),
            ConfigError::Routes => ("SITE_CONFIG_ROUTES_INVALID", Some("routes")),
            ConfigError::Advanced => ("SITE_CONFIG_ADVANCED_INVALID", Some("advanced")),
        };
        let error = Self::new(StatusCode::BAD_REQUEST, code);
        match field {
            Some(field) => error.in_field(field),
            None => error,
        }
    }
}

#[cfg(test)]
impl ApiError {
    /// The stable code, for assertions in tests.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }
}
